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

import re
from django.db.models import Q
from sympy import And, Or, Not, simplify_logic, Symbol
from sympy.logic.boolalg import BooleanTrue, BooleanFalse
from typing import Optional


def merge_qs(qs: list[Optional[Q]], connector: str = Q.AND) -> Optional[Q]:
    result: Optional[Q] = None

    for q in qs:
        if q is None:
            if connector == Q.AND:
                return None

            continue

        result = result._combine(q, conn=connector) if result is not None else q

    return result


def prefix_q_with_relation(q: Q, relation: str) -> Q:
    children = []

    for child in q.children:
        if isinstance(child, Q):
            children.append(prefix_q_with_relation(child, relation))
        elif isinstance(child, tuple):
            children.append((f"{relation}__{child[0]}", *child[1:]))
        else:
            raise (ValueError("Unexpected child", child))

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


def get_sympy_symbols_to_q_children(q: Q, symbols_table: Optional[dict] = None) -> dict:
    if symbols_table is None:
        symbols_table = {}

    for child in q.children:
        if isinstance(child, Q):
            get_sympy_symbols_to_q_children(child, symbols_table)

        else:
            key = f"{child[0]}={re.sub(whitespace_re, '', child[1].__repr__())}"
            while (value := symbols_table.get(key)) is not None and value != child:
                key += "(1)"

            symbols_table[Symbol(key)] = child

    return symbols_table


def get_expression(q: Q, q_children_to_sympy_symbols: dict):
    expression_node = And if q.connector == q.AND else Or

    expressions = []

    for child in q.children:
        if isinstance(child, Q):
            expressions.append(get_expression(child, q_children_to_sympy_symbols))
        else:
            expressions.append(q_children_to_sympy_symbols[child])

    result = expression_node(*expressions)
    if q.negated:
        result = Not(result)

    return result


def _prepare_q(q: Q) -> Q:
    return Q(
        *set(
            dict.fromkeys(
                (
                    _prepare_tuple(child)
                    if not isinstance(child, Q)
                    else _prepare_q(child)
                )
                for child in q.children
            )
        ),
        _connector=q.connector,
        _negated=q.negated,
    )


def _sympy_expression_to_q(
    expression, sympy_symbols_to_q_children: dict, _toplevel=False
) -> bool | Q:
    if isinstance(expression, (bool, BooleanTrue, BooleanFalse)):
        return bool(expression)

    if isinstance(expression, Not):
        # Theoretically not possible to have not with more than 1 arg
        arg = _sympy_expression_to_q(expression.args[0], sympy_symbols_to_q_children)
        if isinstance(arg, Q):
            arg.negated = not arg.negated

            return arg

        else:
            return not arg

    if isinstance(expression, Symbol):
        return (
            sympy_symbols_to_q_children[expression]
            if not _toplevel
            else Q(sympy_symbols_to_q_children[expression])
        )

    connector = Q.AND if isinstance(expression, And) else Q.OR

    return Q(
        *[
            _sympy_expression_to_q(arg, sympy_symbols_to_q_children)
            for arg in expression.args
        ],
        _connector=connector,
    )


def sympy_expression_to_q(
    expression, sympy_symbols_to_q_children: dict, _toplevel=False
) -> bool | Q:
    return _sympy_expression_to_q(
        expression, sympy_symbols_to_q_children, _toplevel=True
    )


def optimize_q(q: Optional[Q], allow_bools=True) -> Q | bool | None:
    if not q:
        return None

    q = _prepare_q(q)

    sympy_to_q_children = get_sympy_symbols_to_q_children(q)
    q_children_to_sympy = {value: key for key, value in sympy_to_q_children.items()}

    expression = get_expression(q, q_children_to_sympy_symbols=q_children_to_sympy)
    simplified_expression = simplify_logic(expression)

    result = sympy_expression_to_q(simplified_expression, sympy_to_q_children)

    if not allow_bools:
        if result is False:
            return None

        if q is True:
            return Q()

    return result
