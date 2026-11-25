#------------------------------------------------------------------------------
# Wyrm — wyrm/history.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Developer: Kwan (browsing history)
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Browsing history (visited pages with title and time), stored locally in SQLite.

Never used by Tor or private windows. Repeated visits to the same page within 30 minutes update one entry
instead of adding duplicates.
"""
from __future__ import annotations

import time

MERGE_SECONDS = 30 * 60
MAX_ROWS = 50_000


class History:
    def __init__(self, path: str):
        from .fileperms import connect
        self.db = connect(path)   # 0600 (B5)
        self.db.execute("CREATE TABLE IF NOT EXISTS visits (id INTEGER PRIMARY KEY, url TEXT NOT NULL, "
                        "title TEXT NOT NULL DEFAULT '', ts REAL NOT NULL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS visits_ts ON visits (ts)")
        # B6: what the user typed in the address bar (autocomplete). Lives here, not in QSettings, so history has
        # one store and a new entry is one row instead of rewriting a 500-item list in the settings file.
        self.db.execute("CREATE TABLE IF NOT EXISTS typed (text TEXT PRIMARY KEY, ts REAL NOT NULL)")
        self.db.commit()

    # ---------------------------------------------------------------- typed address-bar entries (B6)
    TYPED_MAX = 500

    def add_typed(self, text: str) -> None:
        text = (text or "").strip()
        if not text:
            return
        self.db.execute("INSERT INTO typed (text, ts) VALUES (?, ?) ON CONFLICT(text) DO UPDATE SET ts = excluded.ts",
                        (text, time.time()))
        self.db.execute("DELETE FROM typed WHERE text NOT IN (SELECT text FROM typed ORDER BY ts DESC LIMIT ?)",
                        (self.TYPED_MAX,))
        self.db.commit()

    def typed(self, limit: int = 500) -> list[str]:
        return [r[0] for r in self.db.execute("SELECT text FROM typed ORDER BY ts DESC LIMIT ?", (limit,))]

    def clear_typed(self) -> None:
        self.db.execute("DELETE FROM typed")
        self.db.commit()

    def import_typed(self, entries) -> int:
        """One-time migration of the old QSettings list (newest first). Only entries missing here are added,
        ranked below anything already in the database. Returns how many were added."""
        have = set(self.typed(self.TYPED_MAX))
        oldest = self.db.execute("SELECT MIN(ts) FROM typed").fetchone()[0] or time.time()
        added = 0
        for i, text in enumerate(e for e in (entries or []) if isinstance(e, str) and e.strip()):
            text = text.strip()
            if text in have:
                continue
            self.db.execute("INSERT OR IGNORE INTO typed (text, ts) VALUES (?, ?)", (text, oldest - 1 - i))
            have.add(text)
            added += 1
        self.db.execute("DELETE FROM typed WHERE text NOT IN (SELECT text FROM typed ORDER BY ts DESC LIMIT ?)",
                        (self.TYPED_MAX,))
        self.db.commit()
        return added

    def record(self, url: str, title: str = "") -> None:
        if not url.startswith(("http://", "https://")):
            return
        now = time.time()
        row = self.db.execute("SELECT id, ts FROM visits WHERE url = ? ORDER BY ts DESC LIMIT 1", (url,)).fetchone()
        if row and now - row[1] < MERGE_SECONDS:
            self.db.execute("UPDATE visits SET ts = ?, title = CASE WHEN ? != '' THEN ? ELSE title END WHERE id = ?",
                            (now, title, title, row[0]))
        else:
            self.db.execute("INSERT INTO visits (url, title, ts) VALUES (?, ?, ?)", (url, title or "", now))
        self.db.commit()

    def set_title(self, url: str, title: str) -> None:
        if title:
            self.db.execute("UPDATE visits SET title = ? WHERE id = (SELECT id FROM visits WHERE url = ? "
                            "ORDER BY ts DESC LIMIT 1)", (title, url))
            self.db.commit()

    def entries(self, query: str = "", limit: int = 500) -> list[dict]:
        q = f"%{query.strip()}%"
        rows = self.db.execute("SELECT id, url, title, ts FROM visits WHERE url LIKE ? OR title LIKE ? "
                               "ORDER BY ts DESC LIMIT ?", (q, q, limit)).fetchall()
        return [{"id": r[0], "url": r[1], "title": r[2], "ts": r[3]} for r in rows]

    def top_sites(self, scan: int = 300) -> list[dict]:
        """Most-visited pages, most-frequent first (by number of visit sessions, then recency). The caller
        de-duplicates by site. Powers the start page's 'Most visited' tiles, like other browsers."""
        rows = self.db.execute("SELECT url, title, COUNT(*) c, MAX(ts) m FROM visits "
                               "GROUP BY url ORDER BY c DESC, m DESC LIMIT ?", (scan,)).fetchall()
        return [{"url": r[0], "title": r[1], "visits": r[2]} for r in rows]

    def delete(self, entry_id: int) -> None:
        self.db.execute("DELETE FROM visits WHERE id = ?", (int(entry_id),))
        self.db.commit()

    def clear(self) -> None:
        self.db.execute("DELETE FROM visits")
        self.db.commit()
        self.db.execute("VACUUM")

    def count(self) -> int:
        return self.db.execute("SELECT COUNT(*) FROM visits").fetchone()[0]

    def trim(self) -> None:
        self.db.execute("DELETE FROM visits WHERE id NOT IN (SELECT id FROM visits ORDER BY ts DESC LIMIT ?)",
                        (MAX_ROWS,))
        self.db.commit()
