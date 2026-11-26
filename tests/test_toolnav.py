#------------------------------------------------------------------------------
# Wyrm — tests/test_toolnav.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Security panel navigation model: groups stay short, search finds nested tools, pins move to the top."""
from wyrm.panels import toolnav

ALL = [n for _t, items in toolnav.GROUPS for n in items]


def test_every_tool_is_grouped_once_and_described():
    assert len(ALL) == len(set(ALL))
    assert all(len(items) <= 4 for _t, items in toolnav.GROUPS)   # no wall of buttons in one group
    assert set(ALL) == set(toolnav.TOOL_INFO)


def test_search_finds_nested_subtools():
    hits = toolnav.search(toolnav.base_entries(ALL), "repeater")
    assert hits[0]["label"] == "Repeater" and hits[0]["tab"] == "Tools" and hits[0]["sub"] == "Repeater"


def test_search_ranks_label_prefix_before_keyword_matches():
    hits = [e["label"] for e in toolnav.search(toolnav.base_entries(ALL), "web")]
    assert hits[0] == "WebSocket"


def test_search_matches_keywords_and_needs_every_word():
    labels = [e["label"] for e in toolnav.search(toolnav.base_entries(ALL), "sqli")]
    assert labels == ["Audit"]
    assert toolnav.search(toolnav.base_entries(ALL), "jwt zzzz") == []
    assert toolnav.search(toolnav.base_entries(ALL), "   ") == []


def test_sections_pins_on_top_and_collapsed_flag():
    secs = toolnav.sections(toolnav.GROUPS, ["Audit", "Gone"], {"RECON"})
    assert secs[0] == (toolnav.PINNED, ["Audit"], False)
    scanning = next(s for s in secs if s[0] == "SCANNING")
    assert "Audit" not in scanning[1]
    assert next(s for s in secs if s[0] == "RECON")[2] is True


def test_sections_drop_group_emptied_by_pins():
    secs = toolnav.sections(toolnav.GROUPS, ["Shields"])
    assert "PROTECTION" not in [t for t, _n, _f in secs]
    assert toolnav.sections(toolnav.GROUPS, [])[0][0] == "PROTECTION"
