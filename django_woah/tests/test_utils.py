from django.db.models import Q

from django_woah.utils.q import (
    optimize_q,
    move_q_negations_to_leafs,
    _extract_common_from_q,
)


def test_optimize_q_basic1():
    assert optimize_q(Q(a=1)) == Q(a=1)


def test_optimize_q_basic2():
    assert optimize_q(~Q(a=1)) == ~Q(a=1)


def test_optimize_q_basic3():
    assert optimize_q(Q(a=1, _connector=Q.OR)) == Q(a=1, _connector=Q.AND)


def test_optimize_q_basic4():
    assert optimize_q(~Q(a=1, _connector=Q.OR)) == ~Q(a=1, _connector=Q.AND)


def test_optimize_q_1level_simple():
    assert optimize_q(
        Q(Q(a=2), Q(b=3), Q(a=2)),
    ) == Q(a=2, b=3)


def test_optimize_q_1level_simple_case2():
    assert optimize_q(
        Q(a=2, d=4, b=2) | Q(a=2),
    ) == Q(a=2)


def test_optimize_q_3level_simple_case3():
    # This tests for sorting as well
    assert optimize_q(
        Q(Q(Q(Q(Q(a=2))), Q(b=3)), Q(b=3)) & Q(Q(Q(a=2))),
    ) == Q(a=2, b=3)


def test_optimize_q_2level_simple():
    assert optimize_q(
        Q(
            Q(a=2),
            Q(a=2),
            Q(b=3),
        )
        & Q(b=3)
        & Q(a=2)
    ) == Q(
        a=2
    ) & Q(b=3)


def test_optimize_q_1level_extract_common():
    assert optimize_q(
        (Q(a=2) & Q(b=2)) | (Q(a=2) & Q(c=3)),
    ) == Q(("a", 2), Q(b=2) | Q(c=3))


def test_optimize_q_1level_extract_common_and_prune_extras():
    assert optimize_q(
        (Q(a=2) & Q(b=2)) & (Q(a=2) & Q(c=3)) & (Q(d=4) | Q(a=2)),
    ) == Q(a=2, b=2, c=3)


def test_optimize_q_1level_extract_common_case2():
    assert optimize_q(
        (Q(a=2) & Q(b=2, a=2)) | (Q(a=2) & Q(c=3)) | Q(a=2, d=4),
    ) == Q(
        a=2
    ) & (Q(b=2) | Q(c=3) | Q(d=4))


def test_optimize_q_1level_prune_extras():
    assert optimize_q(
        (Q(a=2) & Q(b=2, a=2)) | (Q(a=2, b=2) & Q(c=3)) | (Q(a=2, d=4, b=2) | Q(a=2)),
    ) == Q(a=2)


def test_optimize_q_1level_partially_extract_common():
    assert optimize_q(Q(a=2, b=2) & Q(c=3) & Q(Q(b=2), a=2, c=3)) == Q(a=2, b=2, c=3)


# TODO: get this back working
# def test_optimize_q_negated_1level_simple():
#     assert optimize_q(Q(a=2) & ~Q(a=2)) is False


def test_move_q_negations_to_leafs_basic1():
    assert move_q_negations_to_leafs(Q(a=1)) == Q(a=1)


def test_move_q_negations_to_leafs_basic2():
    assert move_q_negations_to_leafs(~Q(a=1)) == ~Q(a=1)


def test_move_q_negations_to_leafs_basic3():
    assert move_q_negations_to_leafs(Q(a=1, _connector=Q.OR)) == Q(a=1, _connector=Q.OR)


def test_move_q_negations_to_leafs_basic4():
    assert move_q_negations_to_leafs(~Q(a=1, _connector=Q.OR)) == ~Q(
        a=1, _connector=Q.OR
    )


def test_move_q_negations_to_leafs_case1():
    q = ~Q(Q(a=1), ~Q(b=1), a=2)
    assert move_q_negations_to_leafs(q) == ~Q(a=1) | Q(b=1) | ~Q(a=2)


def test_move_q_negations_to_leafs_case2():
    q = ~Q(Q(a=1), ~Q(b=1, c=2, d=3), a=2)
    assert move_q_negations_to_leafs(q) == ~Q(a=1) | Q(b=1, c=2, d=3) | ~Q(a=2)


def test_move_q_negations_to_leafs_case3():
    q = ~Q(Q(a=1), Q(b=1, c=2, d=3), a=2)
    assert move_q_negations_to_leafs(q) == ~Q(a=1) | ~Q(b=1) | ~Q(c=2) | ~Q(d=3) | ~Q(
        a=2
    )


def test_optimize_q_real_usecase_1():
    q = (
        (Q(a=False) & Q(b="abc") & (Q(c=None, d=None) | Q(d="pqr")))
        | (Q(a=False) & Q(b="abc") & (Q(c=None, d=None) | Q(d="ijk")))
        | (Q(a=False) & Q(p="xyz") & Q(b="abc") & (Q(c=None, d=None) | Q(d="ijk")))
    )

    assert optimize_q(q) == Q(
        ("a", False),
        ("b", "abc"),
        Q(
            Q(("c", None), ("d", None)),
            ("d", "ijk"),
            ("d", "pqr"),
            _connector=Q.OR,
        ),
    )


def test_optimize_q_real_usecase_2():
    # TODO: maybe find a different case, as this is kind of hard to track

    q = Q(
        Q(
            ("pk__in", [1]),
            Q(
                ("p_pk_in", [7]),
                Q(
                    Q(("p_knd", "root"), ("m_usr", "acc")),
                    ("p_o", "acc"),
                    _connector=Q.OR,
                ),
            ),
            Q(
                Q(
                    ("pk__in", [2]),
                    Q(
                        Q(
                            ("pk__in", [4]),
                            Q(
                                Q(
                                    ("pk__in", [6]),
                                    Q(
                                        Q(
                                            ("o_pk_in", [3]),
                                            ("o_id_in", [5]),
                                            ("owner", "acc"),
                                            _connector=Q.OR,
                                        ),
                                        Q(
                                            Q(("knd", "root"), ("usr", "acc")),
                                            ("owner", "acc"),
                                            _connector=Q.OR,
                                        ),
                                    ),
                                    _connector=Q.OR,
                                ),
                                Q(
                                    Q(("knd", "root"), ("usr", "acc")),
                                    ("owner", "acc"),
                                    _connector=Q.OR,
                                ),
                            ),
                            _connector=Q.OR,
                        ),
                        Q(
                            Q(("knd", "root"), ("usr", "acc")),
                            ("owner", "acc"),
                            _connector=Q.OR,
                        ),
                    ),
                    _connector=Q.OR,
                ),
                Q(
                    Q(("knd", "root"), ("usr", "acc")),
                    ("owner", "acc"),
                    _connector=Q.OR,
                ),
            ),
            _connector=Q.OR,
        ),
        Q(Q(("knd", "root"), ("usr", "acc")), ("owner", "acc"), _connector=Q.OR),
    )

    # TODO: further extract pk__in into frozenset({1, 2, 4, 6}))

    assert optimize_q(q) == Q(
        ("owner", "acc"),
        Q(
            ("knd", "root"),
            ("usr", "acc"),
            Q(
                ("pk__in", frozenset({1})),
                Q(("p_pk_in", frozenset({7})), ("p_knd", "root"), ("m_usr", "acc")),
                Q(("p_pk_in", frozenset({7})), ("p_o", "acc")),
                ("pk__in", frozenset({2})),
                ("pk__in", frozenset({4})),
                ("pk__in", frozenset({6})),
                ("o_pk_in", frozenset({3})),
                ("o_id_in", frozenset({5})),
                _connector=Q.OR,
            ),
        ),
        _connector=Q.OR,
    )


def test_extract_common_from_q_basic1():
    assert _extract_common_from_q(Q(a=1)) == Q(a=1)


def test_extract_common_from_q_basic2():
    assert _extract_common_from_q(~Q(a=1)) == ~Q(a=1)


def test_extract_common_from_q_basic3():
    assert _extract_common_from_q(Q(a=1, _connector=Q.OR)) == Q(a=1, _connector=Q.AND)


def test_extract_common_from_q_basic4():
    assert _extract_common_from_q(~Q(a=1, _connector=Q.OR)) == ~Q(a=1, _connector=Q.AND)


def test_extract_common_from_q_case1():
    assert _extract_common_from_q(Q(a=2) | Q(Q(a=2) & Q(b=3))) == Q(a=2)


def test_extract_common_from_q_case2():
    assert _extract_common_from_q(Q(a=2, c=3, d=2) | Q(a=2, b=3)) == Q(a=2) & (
        Q(c=3, d=2) | Q(b=3)
    )


def test_extract_common_from_q_case3():
    assert _extract_common_from_q(Q(a=2, b=3, d=2) | Q(a=2, b=3)) == Q(a=2, b=3)


def test_extract_common_from_q_case4():
    assert _extract_common_from_q(Q(a=2, b=3, d=2) | Q(a=2, b=3, e=2)) == Q(
        a=2, b=3
    ) & (Q(d=2) | Q(e=2))


def test_extract_common_from_q_case5():
    assert _extract_common_from_q(Q(~Q(a=2), c=3, d=2) | Q(~Q(a=2), b=3)) == ~Q(a=2) & (
        Q(c=3, d=2) | Q(b=3)
    )


def test_extract_common_from_q_case6():
    # TODO: maybe see if ordering of Q(~Q(a=2), c=3) can be kept
    q = Q(("c", 3), ("d", 2), ~Q(a=2)) | Q(a=2, b=3)

    assert _extract_common_from_q(q) == q


def test_extract_common_from_q_case7():
    # TODO: maybe see if ordering of Q(~Q(a=2), c=3) can be kept

    q = Q(("c", 3), ~Q(a=2)) | Q(a=2, b=3)

    assert _extract_common_from_q(q) == q


def test_extract_common_from_q_case8():
    # AND OF ANDS is not really supported anyway
    q = Q(a=2, b=2, c=3) & Q(~Q(a=2), ~Q(b=3), ~Q(c=3))

    # TODO: at some point this should return False, maybe when calling optimize_q on it...
    assert _extract_common_from_q(q) == q


def test_extract_common_from_q_case9():
    # AND OF ANDS is not really supported anyway
    q = Q(a=2, b=2, c=3) | Q(~Q(a=2), ~Q(b=3), ~Q(c=3))

    # TODO: at some point this should return False, maybe when calling optimize_q on it...
    assert _extract_common_from_q(q) == q


def test_extract_common_from_q_case10():
    q = ~Q(a=2)

    assert _extract_common_from_q(q) == q


def test_extract_common_from_q_case11():
    q = ~Q(a=2) | ~Q(a=3) | ~Q(b=3)

    assert _extract_common_from_q(q) == q


def test_extract_common_from_q_case12():
    q = ~Q(a=2) & ~Q(a=3) & ~Q(b=3)

    assert _extract_common_from_q(q) == q
