#------------------------------------------------------------------------------
# Wyrm — wyrm/security/store.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Engagements (authorized targets + scope) and findings, stored in SQLite."""
from __future__ import annotations

import fnmatch
import ipaddress
import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class Engagement:
    id: int
    name: str
    scope: list[str] = field(default_factory=list)
    block_out_of_scope: bool = False
    notes: str = ""
    created: str = ""

    def in_scope(self, host: str) -> bool | None:
        """True/False for in/out of scope; None when this engagement has no scope (personal mode)."""
        if not self.scope:
            return None
        return host_in_scope(host, self.scope)


def _match(host: str, pattern: str) -> bool:
    pattern = pattern.strip().lower()
    for prefix in ("https://", "http://"):
        if pattern.startswith(prefix):
            pattern = pattern[len(prefix):]
    pattern = pattern.split("/", 1)[0]
    if not pattern:
        return False
    try:  # IP or CIDR
        net = ipaddress.ip_network(pattern, strict=False)
        try:
            return ipaddress.ip_address(host) in net
        except ValueError:
            return False
    except ValueError:
        pass
    if pattern.startswith("*."):  # *.example.com covers the apex and every subdomain
        base = pattern[2:]
        return host == base or host.endswith("." + base)
    return fnmatch.fnmatch(host, pattern)


def host_in_scope(host: str, scope: list[str]) -> bool:
    """Scope entries: example.com, *.example.com, 10.0.0.0/24, api-*.example.com; prefix ! to exclude."""
    host = (host or "").lower().strip(".")
    if not host:
        return False
    excluded = any(_match(host, p[1:]) for p in scope if p.strip().startswith("!"))
    included = any(_match(host, p) for p in scope if p.strip() and not p.strip().startswith("!"))
    return included and not excluded


class Store:
    def __init__(self, path: str):
        from ..fileperms import connect
        self.db = connect(path)   # engagements + findings: owner-only (B5)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, scope TEXT DEFAULT '[]',
                block INTEGER DEFAULT 0, notes TEXT DEFAULT '', created TEXT);
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT, engagement_id INTEGER, title TEXT, severity TEXT,
                url TEXT, description TEXT, evidence TEXT, screenshot BLOB, created TEXT);
            """
        )
        self.db.commit()

    # ---------------------------------------------------------- engagements
    def engagements(self) -> list[Engagement]:
        return [self._eng(r) for r in self.db.execute("SELECT * FROM engagements ORDER BY id DESC")]

    def engagement(self, eid: int) -> Engagement | None:
        r = self.db.execute("SELECT * FROM engagements WHERE id = ?", (eid,)).fetchone()
        return self._eng(r) if r else None

    def save_engagement(self, e: Engagement) -> Engagement:
        scope = json.dumps([s.strip() for s in e.scope if s.strip()])
        if e.id:
            self.db.execute("UPDATE engagements SET name=?, scope=?, block=?, notes=? WHERE id=?",
                            (e.name, scope, int(e.block_out_of_scope), e.notes, e.id))
        else:
            e.created = datetime.now().isoformat(timespec="seconds")
            cur = self.db.execute("INSERT INTO engagements(name, scope, block, notes, created) VALUES (?,?,?,?,?)",
                                  (e.name, scope, int(e.block_out_of_scope), e.notes, e.created))
            e.id = cur.lastrowid
        self.db.commit()
        return e

    def delete_engagement(self, eid: int):
        self.db.execute("DELETE FROM findings WHERE engagement_id = ?", (eid,))
        self.db.execute("DELETE FROM engagements WHERE id = ?", (eid,))
        self.db.commit()

    @staticmethod
    def _eng(r) -> Engagement:
        return Engagement(r["id"], r["name"], json.loads(r["scope"] or "[]"), bool(r["block"]), r["notes"] or "",
                          r["created"] or "")

    # ---------------------------------------------------------- findings
    def findings(self, eid: int) -> list[dict]:
        rows = self.db.execute("SELECT * FROM findings WHERE engagement_id = ? ORDER BY id", (eid,))
        out = [dict(r) for r in rows]
        out.sort(key=lambda f: (SEVERITIES.index(f["severity"]) if f["severity"] in SEVERITIES else 9, f["id"]))
        return out

    def add_finding(self, eid: int, title: str, severity: str, url: str, description: str = "",
                    evidence: str = "", screenshot: bytes | None = None) -> int:
        cur = self.db.execute(
            "INSERT INTO findings(engagement_id, title, severity, url, description, evidence, screenshot, created) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (eid, title, severity, url, description, evidence, screenshot, datetime.now().isoformat(timespec="seconds")),
        )
        self.db.commit()
        return cur.lastrowid

    def update_finding(self, fid: int, **fields):
        allowed = {k: v for k, v in fields.items() if k in ("title", "severity", "url", "description", "evidence")}
        if allowed:
            sets = ", ".join(f"{k} = ?" for k in allowed)
            self.db.execute(f"UPDATE findings SET {sets} WHERE id = ?", (*allowed.values(), fid))
            self.db.commit()

    def delete_finding(self, fid: int):
        self.db.execute("DELETE FROM findings WHERE id = ?", (fid,))
        self.db.commit()

    def counts(self, eid: int) -> dict[str, int]:
        rows = self.db.execute("SELECT severity, COUNT(*) n FROM findings WHERE engagement_id = ? GROUP BY severity",
                               (eid,))
        return {r["severity"]: r["n"] for r in rows}
