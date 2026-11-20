"""Personal reading memory (SQLite): every paper you open is remembered, saved ones are starred.

This is what powers the CiteSee-style link annotation: any page that cites a paper
you have already read or saved gets that link highlighted.
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime


class Library:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute(
            """CREATE TABLE IF NOT EXISTS papers (
                key TEXT PRIMARY KEY,
                title TEXT, url TEXT, meta TEXT,
                saved INTEGER DEFAULT 0,
                visits INTEGER DEFAULT 0,
                first_seen TEXT, last_seen TEXT
            )"""
        )
        self.db.commit()

    @staticmethod
    def _now() -> str:
        return datetime.now().isoformat(timespec="seconds")

    def _ensure(self, key: str, url: str | None = None):
        self.db.execute(
            "INSERT OR IGNORE INTO papers(key, url, first_seen) VALUES (?, ?, ?)", (key, url, self._now())
        )

    def record_visit(self, key: str, url: str):
        self._ensure(key, url)
        self.db.execute(
            "UPDATE papers SET visits = visits + 1, last_seen = ?, url = COALESCE(url, ?) WHERE key = ?",
            (self._now(), url, key),
        )
        self.db.commit()

    def update_meta(self, key: str, meta: dict):
        self._ensure(key, meta.get("url"))
        self.db.execute(
            "UPDATE papers SET meta = ?, title = ? WHERE key = ?", (json.dumps(meta), meta.get("title"), key)
        )
        self.db.commit()

    def set_saved(self, key: str, saved: bool, meta: dict | None = None):
        self._ensure(key, meta.get("url") if meta else None)
        if meta:
            self.update_meta(key, meta)
        self.db.execute("UPDATE papers SET saved = ? WHERE key = ?", (int(saved), key))
        self.db.commit()

    def get(self, key: str) -> dict | None:
        row = self.db.execute("SELECT * FROM papers WHERE key = ?", (key,)).fetchone()
        return self._row(row) if row else None

    def status(self, key: str) -> str | None:
        row = self.db.execute("SELECT saved, visits FROM papers WHERE key = ?", (key,)).fetchone()
        if not row:
            return None
        return "saved" if row["saved"] else ("read" if row["visits"] else None)

    def status_map(self) -> dict[str, str]:
        rows = self.db.execute("SELECT key, saved, visits FROM papers WHERE saved = 1 OR visits > 0")
        return {r["key"]: "saved" if r["saved"] else "read" for r in rows}

    def saved(self) -> list[dict]:
        rows = self.db.execute("SELECT * FROM papers WHERE saved = 1 ORDER BY last_seen DESC, first_seen DESC")
        return [self._row(r) for r in rows]

    def recent(self, n: int = 8) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM papers WHERE visits > 0 ORDER BY last_seen DESC LIMIT ?", (n,)
        )
        return [self._row(r) for r in rows]

    @staticmethod
    def _row(r: sqlite3.Row) -> dict:
        d = dict(r)
        d["meta"] = json.loads(d["meta"]) if d.get("meta") else None
        return d
