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

import sqlite3
import time

MERGE_SECONDS = 30 * 60
MAX_ROWS = 50_000


class History:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.execute("CREATE TABLE IF NOT EXISTS visits (id INTEGER PRIMARY KEY, url TEXT NOT NULL, "
                        "title TEXT NOT NULL DEFAULT '', ts REAL NOT NULL)")
        self.db.execute("CREATE INDEX IF NOT EXISTS visits_ts ON visits (ts)")
        self.db.commit()

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
