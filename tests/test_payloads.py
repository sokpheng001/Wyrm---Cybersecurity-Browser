#------------------------------------------------------------------------------
# Wyrm — tests/test_payloads.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""The Intruder payload library: every set is grouped, described, and non-empty; numbers() ranges are correct."""
from wyrm.security import payloads as p


def test_every_list_is_categorised_once_and_described():
    grouped = [n for _c, names in p.CATEGORIES for n in names]
    assert len(grouped) == len(set(grouped))            # no list in two categories
    assert set(grouped) == set(p.LISTS) == set(p.META)  # categories, payloads and descriptions line up


def test_lists_are_non_empty_and_stringy():
    assert len(p.LISTS) >= 15
    for name, items in p.LISTS.items():
        assert items, f"{name} is empty"
        assert all(isinstance(x, str) and x != "" for x in items), name
        assert p.META[name].strip()


def test_numbers_ranges():
    assert p.numbers(1, 5) == ["1", "2", "3", "4", "5"]
    assert p.numbers(0, 10, 5) == ["0", "5", "10"]
    assert p.numbers(5, 1, -2) == ["5", "3", "1"]
    assert p.numbers(1, 3, 0) == ["1", "2", "3"]        # step 0 is treated as 1, not a crash
