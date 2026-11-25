#------------------------------------------------------------------------------
# Wyrm — tests/test_fileperms.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""B5: local databases/JSON data are owner-only (0600) and the data directory is 0700; existing files are fixed."""
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wyrm import fileperms  # noqa: E402
from wyrm.history import History  # noqa: E402
from wyrm.security.store import Store  # noqa: E402

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")


def mode(p):
    return stat.S_IMODE(os.stat(p).st_mode)


def test_new_databases_are_private(tmp_path):
    os.umask(0o022)   # the default that produced 0644 before
    h = History(str(tmp_path / "history.db"))
    h.record("https://example.com/", "x")
    Store(str(tmp_path / "hidden.db"))
    assert mode(tmp_path / "history.db") == 0o600
    assert mode(tmp_path / "hidden.db") == 0o600


def test_json_writer_is_private_and_atomic(tmp_path):
    os.umask(0o022)
    f = tmp_path / "sessions.json"
    fileperms.write_text(f, '{"a": 1}')
    assert mode(f) == 0o600 and f.read_text() == '{"a": 1}' and not (tmp_path / "sessions.json.tmp").exists()


def test_harden_fixes_existing_install(tmp_path):
    d = tmp_path / "Wyrm"
    (d / "addons" / "x").mkdir(parents=True)
    (d / "cache").mkdir()
    for f in ("history.db", "hidden.db", "workflows.json", "addons/x/storage.json"):
        (d / f).write_text("x")
        os.chmod(d / f, 0o644)
    (d / "cache" / "blob.json").write_text("x")
    os.chmod(d / "cache" / "blob.json", 0o644)
    os.chmod(d, 0o755)
    assert fileperms.harden(d) >= 5
    assert mode(d) == 0o700
    for f in ("history.db", "hidden.db", "workflows.json", "addons/x/storage.json"):
        assert mode(d / f) == 0o600, f
    assert mode(d / "cache" / "blob.json") == 0o644   # Chromium-managed folders are left alone
