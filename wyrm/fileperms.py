#------------------------------------------------------------------------------
# Wyrm — wyrm/fileperms.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Owner-only permissions for Wyrm's local data (B5).

history.db and hidden.db (engagements + findings) used to be created 0644 — readable by every local account.
Every SQLite database and JSON data file is now created 0600 and the data directory 0700, and existing files are
fixed on startup. POSIX only: on Windows the per-user AppData ACL already restricts access, so these are no-ops.
"""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

FILE_MODE = 0o600
DIR_MODE = 0o700
_POSIX = sys.platform != "win32"
# data files we own (Chromium manages its own profile/cache files, which it already creates 0600)
_DATA_SUFFIXES = (".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".json", ".log", ".pem", ".key")
_SKIP_DIRS = {"cache", "profiles", "pdtools-update", "bin", "backgrounds", "ui", "favicons", "filters"}


def private_dir(path) -> Path:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    if _POSIX:
        try:
            os.chmod(p, DIR_MODE)
        except OSError:
            pass
    return p


def _chmod_file(p: Path) -> None:
    if _POSIX:
        try:
            if p.is_file() and (p.stat().st_mode & 0o777) != FILE_MODE:
                os.chmod(p, FILE_MODE)
        except OSError:
            pass


def touch_private(path) -> Path:
    """Create `path` 0600 if missing (atomic with O_CREAT, so it's never briefly world-readable) or tighten it."""
    p = Path(path)
    if _POSIX:
        try:
            fd = os.open(p, os.O_CREAT | os.O_WRONLY, FILE_MODE)
            os.close(fd)
        except OSError:
            pass
    _chmod_file(p)
    return p


def connect(path) -> sqlite3.Connection:
    """sqlite3.connect() for a private database: the file and its -wal/-shm/-journal siblings are 0600."""
    touch_private(path)
    db = sqlite3.connect(str(path))
    for suf in ("-wal", "-shm", "-journal"):
        _chmod_file(Path(str(path) + suf))
    return db


def write_text(path, text: str, encoding: str = "utf-8") -> None:
    """Write a private data file (0600), replacing it atomically so a crash never leaves it half-written."""
    p = Path(path)
    tmp = p.with_name(p.name + ".tmp")
    if _POSIX:
        fd = os.open(tmp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, FILE_MODE)
        with os.fdopen(fd, "w", encoding=encoding) as fh:
            fh.write(text)
    else:
        tmp.write_text(text, encoding=encoding)
    os.replace(tmp, p)
    _chmod_file(p)


def harden(data_dir, max_depth: int = 3) -> int:
    """Startup fix-up for existing installs: data dir (and our own subfolders) 0700, data files 0600.
    Returns how many entries were tightened. Bounded walk; Chromium/cache/tool folders are skipped."""
    if not _POSIX:
        return 0
    root = Path(data_dir)
    if not root.is_dir():
        return 0
    fixed = 0

    def tighten(p: Path, mode: int):
        nonlocal fixed
        try:
            if (p.stat().st_mode & 0o777) != mode:
                os.chmod(p, mode)
                fixed += 1
        except OSError:
            pass

    tighten(root, DIR_MODE)
    stack = [(root, 0)]
    while stack:
        d, depth = stack.pop()
        try:
            entries = list(os.scandir(d))
        except OSError:
            continue
        for e in entries:
            p = Path(e.path)
            if e.is_symlink():
                continue
            if e.is_dir():
                if depth < max_depth and e.name not in _SKIP_DIRS:
                    tighten(p, DIR_MODE)
                    stack.append((p, depth + 1))
            elif e.name.endswith(_DATA_SUFFIXES):
                tighten(p, FILE_MODE)
    return fixed
