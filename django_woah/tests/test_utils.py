from django.db.models import Q

from django_woah.utils.q import optimize_q


def test_optimize_q_1level_simple():
    assert optimize_q(
        Q(Q(a=2), Q(b=3), Q(a=2)),
    ) == Q(
        a=2
    ) & Q(b=3)


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
    ) == Q(
        a=2
    ) & (Q(b=2) | Q(c=3))


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


def test_optimize_q_negated_1level_simple():
    assert optimize_q(Q(a=2) & ~Q(a=2)) is False
