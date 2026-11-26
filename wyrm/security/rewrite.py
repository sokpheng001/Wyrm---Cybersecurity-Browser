#------------------------------------------------------------------------------
# Wyrm — wyrm/security/rewrite.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Match & Replace rules (Burp / Caido style): rewrite request headers for in-scope hosts.

A convenience for authorized testing: set a custom User-Agent, add an auth header to every request, or
rewrite a header value with a regex. Rules only apply to hosts in the active engagement's scope, and only
to request headers the browser is already sending. Stored per engagement in the engagement store's settings.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field


@dataclass
class Rule:
    enabled: bool = True
    name: str = ""
    host_glob: str = "*"          # only apply when the request host matches this glob
    header: str = ""              # header name to set / rewrite (e.g. "User-Agent", "X-Forwarded-For")
    match: str = ""               # optional regex; empty = set the header outright
    replace: str = ""             # replacement value (or the full value when match is empty)
    remove: bool = False          # remove the header instead of setting it

    def applies(self, host: str) -> bool:
        if not self.enabled or not self.header:
            return False
        pat = "^" + re.escape(self.host_glob).replace(r"\*", ".*") + "$"
        return re.match(pat, host or "", re.I) is not None


@dataclass
class RuleSet:
    rules: list = field(default_factory=list)

    @classmethod
    def load(cls, raw: str | None) -> "RuleSet":
        try:
            data = json.loads(raw) if raw else []
            return cls([Rule(**{k: r.get(k, getattr(Rule, k, "")) for k in Rule.__annotations__}) for r in data])
        except (ValueError, TypeError):
            return cls([])

    def dump(self) -> str:
        return json.dumps([asdict(r) for r in self.rules])

    # ---- shareable import/export (a file teams can pass around), separate from the compact per-engagement dump
    EXPORT_KEY = "wyrm-match-replace"

    def export_text(self) -> str:
        """Pretty JSON wrapped with a format marker, for an export file."""
        return json.dumps({"format": self.EXPORT_KEY, "version": 1,
                           "rules": [asdict(r) for r in self.rules]}, indent=2)

    @classmethod
    def parse_rules(cls, text: str) -> list:
        """Rules from an export file or a bare JSON list. Raises ValueError on anything else, so the UI can
        tell the user the file isn't a rule set (rather than silently importing nothing)."""
        data = json.loads(text)
        if isinstance(data, dict):
            if data.get("format") not in (cls.EXPORT_KEY, None):
                raise ValueError("not a Wyrm Match & Replace export")
            data = data.get("rules", [])
        if not isinstance(data, list):
            raise ValueError("expected a list of rules")
        out = []
        for r in data:
            if not isinstance(r, dict):
                raise ValueError("each rule must be an object")
            out.append(Rule(**{k: r.get(k, getattr(Rule, k, "")) for k in Rule.__annotations__}))
        return out

    def active(self) -> bool:
        return any(r.enabled and r.header for r in self.rules)

    def apply(self, host: str, headers: dict[str, str]) -> dict[str, str]:
        """Return {header: new_value}; a value of None means remove. Only changed headers are returned."""
        changes: dict[str, str | None] = {}
        for r in self.rules:
            if not r.applies(host):
                continue
            if r.remove:
                if r.header in headers:
                    changes[r.header] = None
                continue
            if r.match:
                try:
                    cur = headers.get(r.header, "")
                    new = re.sub(r.match, r.replace, cur)
                except re.error:
                    continue
            else:
                new = r.replace
            changes[r.header] = new
        return changes
