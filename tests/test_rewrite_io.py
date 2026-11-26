#------------------------------------------------------------------------------
# Wyrm — tests/test_rewrite_io.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Match & Replace rule sets: shareable import/export round-trips and rejects junk."""
import pytest

from wyrm.security.rewrite import Rule, RuleSet


def _sample():
    return RuleSet([Rule(True, "UA", "*", "User-Agent", "", "Wyrm/1.0"),
                    Rule(False, "XFF", "api.*", "X-Forwarded-For", "", "127.0.0.1", remove=True)])


def test_export_then_import_round_trip():
    rules = RuleSet.parse_rules(_sample().export_text())
    assert [r.name for r in rules] == ["UA", "XFF"]
    assert rules[1].host_glob == "api.*" and rules[1].enabled is False and rules[1].remove is True


def test_export_has_format_marker_and_is_pretty():
    txt = _sample().export_text()
    assert '"format": "wyrm-match-replace"' in txt and "\n" in txt


def test_import_accepts_bare_dump_list():
    assert len(RuleSet.parse_rules(_sample().dump())) == 2


def test_import_fills_defaults_for_missing_fields():
    rules = RuleSet.parse_rules('[{"header": "Authorization", "replace": "Bearer x"}]')
    assert rules[0].header == "Authorization" and rules[0].enabled is True and rules[0].host_glob == "*"


@pytest.mark.parametrize("bad", [
    '{"format": "something-else", "rules": []}',
    '"just a string"',
    "42",
    '{"rules": [5]}',
    "not json at all",
])
def test_import_rejects_non_rulesets(bad):
    with pytest.raises(ValueError):
        RuleSet.parse_rules(bad)
