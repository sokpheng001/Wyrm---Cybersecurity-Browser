#------------------------------------------------------------------------------
# Wyrm — tests/test_diff.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Comparer diffs: word-level inline and the side-by-side line_diff alignment."""
from wyrm.security import tools as t


def test_word_diff_marks_insert_and_delete():
    ops = t.word_diff("the quick fox", "the slow fox")
    assert ("equal", "the ") in ops
    assert ("delete", "quick") in ops and ("insert", "slow") in ops


def test_diff_stats_ratio_and_lengths():
    st = t.diff_stats("abcd", "abce")
    assert st["len_a"] == 4 and st["len_b"] == 4
    assert 0 <= st["ratio"] <= 100


def test_line_diff_equal_replace_insert_delete():
    rows = t.line_diff("a\nb\nc\nd", "a\nB\nc\ne\nf")
    assert rows[0] == {"kind": "equal", "lno_a": 1, "left": "a", "lno_b": 1, "right": "a"}
    assert any(r["kind"] == "replace" and r["left"] == "b" and r["right"] == "B" for r in rows)
    # 1-based line numbers, and every row carries all five keys
    assert all(set(r) == {"kind", "lno_a", "left", "lno_b", "right"} for r in rows)


def test_line_diff_pure_insert_and_delete_and_empty():
    assert t.line_diff("x", "x\ny")[-1] == {"kind": "insert", "lno_a": None, "left": None,
                                            "lno_b": 2, "right": "y"}
    assert t.line_diff("x\ny", "x")[-1] == {"kind": "delete", "lno_a": 2, "left": "y",
                                            "lno_b": None, "right": None}
    assert t.line_diff("", "") == []
