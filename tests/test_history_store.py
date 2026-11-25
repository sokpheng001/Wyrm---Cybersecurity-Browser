#------------------------------------------------------------------------------
# Wyrm — tests/test_history_store.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""B6: history.db is the only history store; the old QSettings history/entries list is migrated once and removed."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wyrm.history import History  # noqa: E402


class FakeSettings:
    def __init__(self, **kv):
        self.d = dict(kv)

    def value(self, key, default=None, type=None):  # noqa: A002
        return self.d.get(key, default)

    def remove(self, key):
        self.d.pop(key, None)


def _chrome(db, settings):
    from wyrm.mainwindow.chrome import ChromeMixin
    o = ChromeMixin.__new__(ChromeMixin)
    o.history_db, o.settings = db, settings
    return o


def test_typed_entries_round_trip(tmp_path):
    h = History(str(tmp_path / "history.db"))
    for t in ("a.com", "b.com", "a.com"):
        h.add_typed(t)
    assert h.typed() == ["a.com", "b.com"]
    h.clear_typed()
    assert h.typed() == []


def test_typed_is_capped(tmp_path):
    h = History(str(tmp_path / "history.db"))
    for i in range(History.TYPED_MAX + 25):
        h.add_typed(f"site{i}.com")
    assert len(h.typed(10_000)) == History.TYPED_MAX


def test_legacy_settings_list_migrates_once(tmp_path):
    import pytest
    pytest.importorskip("PySide6")
    h = History(str(tmp_path / "history.db"))
    h.add_typed("already.com")
    legacy = [f"old{i}.com" for i in range(577)] + ["already.com"]
    s = FakeSettings(**{"history/entries": legacy})
    got = _chrome(h, s)._load_typed_history()
    assert "history/entries" not in s.d                         # QSettings key deleted
    assert got[0] == "already.com" and got[1] == "old0.com"     # DB entries rank first, legacy order kept
    assert len(got) == 500 and got.count("already.com") == 1 and len(h.typed(10_000)) == 500
    assert _chrome(h, s)._load_typed_history() == got           # second launch: nothing re-imported
