#  Copyright 2024 Pressinfra SRL
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
from collections import defaultdict

import itertools
import re
import time

from django.db.models import Q
from typing import Optional, Iterable


def merge_qs(
    qs: Iterable[Optional[Q]], connector: str = Q.AND, simplify=True
) -> Optional[Q]:
    result: Optional[Q] = None

    for q in qs:
        if q is None:
            if connector == Q.AND:
                return None

            continue

        result = result._combine(q, conn=connector) if result is not None else q

    if simplify:
        while isinstance(result, Q):
            children_count = len(result.children)
            if children_count >= 2:
                break
            elif children_count == 1:
                if isinstance(result.children, Q):
                    result = result.children[0]
                    continue

            result.connector = Q.AND
            break
    elif result is not None:
        result.connector = connector

    return result


def prefix_q_with_relation(q: Q, relation: str) -> Q:
    children = []

    for child in q.children:
        if isinstance(child, Q):
            children.append(prefix_q_with_relation(child, relation))
        elif isinstance(child, tuple):
            prefixed_relation = (
                f"{relation}__{child[0]}" if child[0] != "*" else relation
            )

            children.append((prefixed_relation, *child[1:]))
        else:
            raise ValueError("Unexpected child", child)

    return Q(*children, _connector=q.connector, _negated=q.negated)


def pop_parts_of_q(q: Q, matcher) -> Q:
    children = []

    for child in q.children:
        if isinstance(child, Q):
            children.append(pop_parts_of_q(child, matcher))
        elif isinstance(child, tuple):
            if matcher(*child):
                continue

            children.append((child[0], *child[1:]))
        else:
            raise ValueError("Unexpected child", child)

    return Q(*children, _connector=q.connector, _negated=q.negated)


def remove_prefix_relation_from_q(q: Q, relation: str) -> Q:
    children = []
    prefix = f"{relation}__"

    for child in q.children:
        if isinstance(child, Q):
            children.append(remove_prefix_relation_from_q(child, relation))
        elif isinstance(child, tuple):
            stripped_relation = child[0]

            if stripped_relation.startswith(prefix):
                stripped_relation = stripped_relation[len(prefix) :]

            if not stripped_relation:
                stripped_relation = "*"

            children.append((stripped_relation, *child[1:]))
        else:
            raise ValueError("Unexpected child", child)

    return Q(*children, _connector=q.connector, _negated=q.negated)


def get_object_relation(obj, relation: str):
    if relation == "*":
        return obj

    for intermediary_attr in relation.split("__"):
        obj = getattr(obj, intermediary_attr)

    return obj


def verify_resource_by_q(resource, q: Q) -> bool:
    result = True

    for child in q.children:
        if q.connector == Q.OR:
            operator = result.__or__
        elif q.connector == Q.AND:
            operator = result.__and__
        else:
            raise ValueError("Unexpected Q operator", q.connector)

        if isinstance(child, Q):
            result = operator(verify_resource_by_q(resource, child))
        elif isinstance(child, tuple):
            return get_object_relation(resource, child[0]) == child[1]
        else:
            raise ValueError("Unexpected child", child)

    return result


def _prepare_tuple(t: tuple) -> tuple:
    key, value = t
    if isinstance(value, list):
        value = frozenset(value)

    if key == "*":
        return "pk", value.pk

    key = key.replace("__*", "").replace("*__", "")

    return key, value


whitespace_re = re.compile(r"\s+")


def _number_to_letters(n, max_length=None):
    alphabet = "abcdefghijklmnopqrstuvwxyz"

    if n == 0:
        return alphabet[0]

    if n < 0:
        alphabet = alphabet[::-1]
        n = abs(n)

    result = ""

    while n > 0:
        result += alphabet[n % len(alphabet)]
        n //= len(alphabet)

    if max_length:
        result = result[-(max_length + 1) : -1]

    return result


def _prepare_q(q: Q, initial=True) -> Q:
    q = Q(
        *(
            dict.fromkeys(
                (
                    _prepare_tuple(child)
                    if not isinstance(child, Q)
                    else _prepare_q(child, initial=False)
                )
                for child in q.children
            )
        ),
        _connector=q.connector,
        _negated=q.negated,
    )

    if not initial and not q.negated and len(q.children) == 1:
        return q.children[0]

    return q


def optimize_q(q: Optional[Q], allow_bools=True) -> Q | bool | None:
    """
    Turns a Q that logically translate to something like
        (e & f & (g | (b & c))) | (e & f & (h | (b & c))) | (d & e & f & (a | (b & c)))
    into a more simplified form like
        (e & f) & (g | h | (b & c))
    (where you can see `a` and `d` are even completely eliminated from the Q)
    (the corresponding test can be found at `test_optimize_q_real_usecase_1`)
    """

    if q is None:
        return None

    # t = time.time()
    q = move_q_negations_to_leafs(q)
    # print(f'move_q_negations_to_leafs: {"%.4f" % (time.time() - t)}s')

    # t = time.time()
    q = _flatten_q(q)
    # print(f'_flatten_q: {"%.4f" % (time.time() - t)}s')

    # t = time.time()
    q = _prepare_q(q)
    # print(f'_prepare_q: {"%.4f" % (time.time() - t)}s')

    # t = time.time()
    q = _extract_common_from_q(q)
    # print(f'_extract_common_from_q: {"%.4f" % (time.time() - t)}s')

    # TODO: write _extract_common_from_q such that a second _prepare_q is not necessary;
    #       currently Q(A) inside other Qs are not denested, unless _prepare_q is called after or at the start of every
    #       _extract_common_from_q call
    q = _prepare_q(q)

    # TODO: In the resulting non extracted remainder, we could check for __in in the predicate keys and see if we can
    #       simplify further, and check for cases that guarantee that the Q is always False or True...

    return q


def move_q_negations_to_leafs(q: Q) -> Q:
    children = []
    opposite_connector = Q.AND if q.connector == Q.OR else Q.OR

    if not q.children or len(q.children) == 1 and isinstance(q.children[0], tuple):
        return q

    for child in q.children:
        if q.negated:
            if isinstance(child, tuple):
                children.append(Q(child, _negated=True))
            else:
                children.append(
                    move_q_negations_to_leafs(
                        Q(
                            *child.children,
                            _connector=child.connector,
                            _negated=not child.negated,
                        )
                    )
                )

        else:
            if isinstance(child, tuple):
                children.append(Q(child))
            else:
                children.append(move_q_negations_to_leafs(child))

    q = merge_qs(
        children,
        connector=opposite_connector if q.negated else q.connector,
    )
    return q


def _flatten_q(q: Q) -> Q:
    """
    :param q: A Q which is assumed to only have negated forms in the leafs/extremities. See `move_q_negation_to_leafs`.
    :return: A Q with one of the following forms:
        - 2-level Q(OR: Q(AND: ...), Q(AND: ...), ...)
        - 1-level Q(OR: ...)
        - 1-level Q(AND: ...)
    """

    if q.negated:
        # Since we assume that only leafs are negated, we can standardize them to use connector = Q.AND
        q.connector = Q.AND
        return q

    if q.connector == Q.OR:
        multipliers = []

        for child in q.children:
            if isinstance(child, tuple):
                multipliers.append(Q(child))

            else:
                flattened_q = _flatten_q(child)

                if flattened_q.negated or flattened_q.connector == Q.AND:
                    flattened_q.connector = Q.AND
                    multipliers.append(flattened_q)
                    continue

                # flattened_q.connector == Q.OR
                multipliers += flattened_q.children

        if not multipliers:
            return q

        return merge_qs(multipliers, connector=q.OR)

    # if q.connector == Q.AND:
    children = []
    multipliers = []

    for child in q.children:
        if isinstance(child, tuple):
            children.append(Q(child))
        else:
            flattened_q = _flatten_q(child)

            if flattened_q.negated:
                flattened_q.connector = Q.AND
                children.append(flattened_q)
                continue

            elif flattened_q.connector == Q.AND:
                children += flattened_q.children

            elif flattened_q.connector == Q.OR:
                multipliers.append(
                    [
                        grandchild if isinstance(grandchild, Q) else Q(grandchild)
                        for grandchild in flattened_q.children
                    ]
                )

    if children:
        children = merge_qs(
            [child if isinstance(child, Q) else Q(child) for child in children],
            connector=Q.AND,
        )
        multipliers.insert(0, [children])

    q = merge_qs(
        [merge_qs(product) for product in itertools.product(*multipliers)],
        connector=Q.OR,
    )
    if not q.negated and len(q.children) == 1 and isinstance(q.children[0], Q):
        q = q.children[0]

    return q


def _extract_common_from_q(q: Q) -> Q:
    """
    :param q: Q is expected to be:
              - either DNF form (OR of ANDs);
              - have a single level, meaning no Q nesting

              (note that a negated Q doesn't count for nesting as long as the Q.children consists of a single tuple)
              (something returned by _flatten_q qualifies for the above)
    """

    child_occurrences = defaultdict(lambda: [])
    negated_child_occurrences = defaultdict(lambda: [])

    for index, child in enumerate(q.children):
        if isinstance(child, tuple):
            # print("APP1", child, index)
            child_occurrences[child].append((index,))

        elif isinstance(child, Q):
            for subindex, grandchild in enumerate(child.children):
                if isinstance(grandchild, tuple):
                    if child.negated:
                        # print("APP2N", grandchild, index, subindex)
                        negated_child_occurrences[grandchild].append((index, subindex))
                    else:
                        # print("APP2", grandchild, index, subindex)
                        child_occurrences[grandchild].append((index, subindex))
                elif isinstance(grandchild, Q):
                    assert len(grandchild.children) == 1, str(grandchild.children)
                    if grandchild.negated:
                        assert not child.negated

                        # print("APP3N", grandchild.children[0], index, subindex)
                        negated_child_occurrences[grandchild.children[0]].append(
                            (index, subindex)
                        )
                    else:
                        # print("APP2", grandchild, index, subindex)
                        child_occurrences[grandchild.children[0]].append(
                            (index, subindex)
                        )

    biggest_occurrence = 0
    popular_child = None
    negated = False

    for child, occurrences in child_occurrences.items():
        count = len(occurrences)
        if count > biggest_occurrence:
            biggest_occurrence = count
            popular_child = child

    for child, occurrences in negated_child_occurrences.items():
        count = len(occurrences)
        if count > biggest_occurrence:
            biggest_occurrence = count
            popular_child = child
            negated = True

    occurrences = negated_child_occurrences if negated else child_occurrences

    if biggest_occurrence >= (len(q.children) / 3) > 0:
        ids = set(index_tuple[0] for index_tuple in occurrences[popular_child])

        children_with_extraction_performed = []
        remaining_children = [
            child for index, child in enumerate(q.children) if index not in ids
        ]

        # Usually we would only consider `negated` if all we were ever to get was DNF-like forms, but to also handle
        # simple case like _extract_common_from_q(~Q(a=1)) we consider q.negated too
        # TODO: verify that this is not harmful in unexpected ways
        extracted_q = Q(popular_child, _negated=q.negated or negated)

        for index_tuple in occurrences[popular_child]:
            if len(index_tuple) == 1:
                if q.connector == Q.OR:
                    children_with_extraction_performed = []
                    break

            else:
                # There's a subindex in there, so we know child is Q

                child = q.children[index_tuple[0]]
                child = Q(
                    *[
                        grandchild
                        for index, grandchild in enumerate(child.children)
                        if index != index_tuple[1]
                    ],
                    _negated=child.negated,
                )

                if child.children:
                    children_with_extraction_performed.append(child)
                    continue

                if q.connector == Q.OR:
                    children_with_extraction_performed = []
                    break

        if children_with_extraction_performed:
            extracted_q &= _extract_common_from_q(
                Q(
                    *children_with_extraction_performed,
                    _connector=q.connector,
                    _negated=q.negated,
                )
            )

        if remaining_children:
            extracted_q = merge_qs(
                [
                    extracted_q,
                    _extract_common_from_q(
                        Q(
                            *remaining_children,
                            _connector=q.connector,
                            _negated=q.negated,
                        )
                    ),
                ],
                connector=q.connector,
            )

        q = extracted_q

    return q


def repr_q(q: Q) -> str:
    reprs = []

    for child in q.children:
        if isinstance(child, tuple):
            reprs.append(f"({child[0].__repr__()}, {child[1].__repr__()})")
        elif isinstance(child, Q):
            if child.connector == q.connector and child.negated == q.negated == False:
                for grandchild in child.children:
                    if isinstance(child, tuple):
                        reprs.append(
                            f"({grandchild[0].__repr__()}, {grandchild[1].__repr__()})"
                        )
                    elif isinstance(grandchild, Q):
                        reprs.append(repr_q(grandchild))
            else:
                reprs.append(repr_q(child))

    extras = ""
    if q.connector == Q.OR:
        extras = ", _connector=Q.OR"

    if q.negated:
        extras += ", _negated=True"

    return f"Q({', '.join(reprs)}{extras})"
