#------------------------------------------------------------------------------
# Wyrm — wyrm/security/audit/checks.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Sopi, Kwan
#------------------------------------------------------------------------------
"""Active checks. Each check's run(point, build, send, baseline, rand) returns a finding dict or None.

`send(url, headers, body)` performs one request and returns {"status", "headers" (lower-cased dict), "text",
"location", "url"} — or None on a network error. Checks are safe: no brute force, small fixed payload sets,
evidence confirmed against the response (and the baseline, to avoid false positives).
"""
from __future__ import annotations

import re

REDIRECT_NAMES = {"url", "uri", "next", "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
                  "return_to", "dest", "destination", "continue", "to", "goto", "out", "target", "r", "u"}

_SQL_ERRORS = re.compile("|".join([
    r"SQL syntax.*MySQL", r"Warning.*\bmysqli?_", r"MySqlException", r"valid MySQL result", r"check the manual that corresponds to your (MySQL|MariaDB)",
    r"PostgreSQL.*ERROR", r"pg_query\(\)", r"PG::\w*Error", r"syntax error at or near",
    r"ORA-\d{5}", r"Oracle error", r"quoted string not properly terminated",
    r"Microsoft OLE DB Provider for SQL Server", r"Unclosed quotation mark after the character string",
    r"Microsoft SQL Native Client error", r"SQLServer JDBC Driver", r"\bSqlException\b",
    r"System\.Data\.SQLite\.SQLiteException", r"sqlite3\.\w*Error", r'near ".*": syntax error',
    r"SQLSTATE\[", r"Incorrect syntax near",
]), re.I)

_PASSWD = re.compile(r"root:.*?:0:0:", re.S)
_WININI = re.compile(r"\[(fonts|extensions|mci extensions)\]", re.I)


def _finding(check, point, payload, evidence, confidence, resp):
    return {"check": check.key, "title": check.title, "severity": check.severity, "confidence": confidence,
            "loc": point["loc"], "param": point["name"], "payload": payload, "evidence": evidence,
            "status": resp.get("status"), "url": resp.get("url", "")}


class ReflectedXSS:
    key, title, severity = "xss", "Reflected XSS", "high"

    def run(self, point, build, send, baseline, rand):
        marker = f"wz{rand}"
        payload = f"{marker}<img src=x onerror=alert(1)>"
        r = send(*build(payload))
        if r and payload in r["text"]:
            return _finding(self, point, payload,
                            "The payload was reflected unescaped in the response — HTML/JS can be injected.",
                            "firm", r)
        probe = f'{marker}"\'><svg/onload=1>'
        r2 = send(*build(probe))
        if r2 and probe in r2["text"]:
            return _finding(self, point, probe,
                            "Angle brackets and quotes were reflected unescaped; likely XSS (verify the context).",
                            "tentative", r2)
        return None


class SqlError:
    key, title, severity = "sqli", "SQL injection (error-based)", "high"

    def run(self, point, build, send, baseline, rand):
        base = point.get("value", "")
        if baseline and _SQL_ERRORS.search(baseline.get("text", "")):
            return None   # the page already shows a SQL error without us — not our injection
        for inj in ("'", '"', "')", "' AND '1'='2"):
            r = send(*build(base + inj))
            if r and _SQL_ERRORS.search(r["text"]):
                m = _SQL_ERRORS.search(r["text"])
                return _finding(self, point, base + inj,
                                f"A database error appeared after injecting {inj!r}: …{m.group(0)[:120]}…",
                                "firm", r)
        return None


class Ssti:
    key, title, severity = "ssti", "Server-side template injection", "high"

    def run(self, point, build, send, baseline, rand):
        product = "1787569"   # 1337*1337, distinctive
        for expr in ("{{1337*1337}}", "${1337*1337}", "#{1337*1337}", "<%= 1337*1337 %>", "{1337*1337}"):
            r = send(*build(expr))
            if r and product in r["text"] and expr not in r["text"]:
                return _finding(self, point, expr,
                                f"The template expression {expr} was evaluated to {product} — template injection.",
                                "firm", r)
        return None


class PathTraversal:
    key, title, severity = "traversal", "Path traversal", "high"

    def run(self, point, build, send, baseline, rand):
        for payload in ("../../../../../../../../etc/passwd", "....//....//....//....//etc/passwd",
                        "..\\..\\..\\..\\..\\..\\windows\\win.ini"):
            r = send(*build(payload))
            if not r:
                continue
            if _PASSWD.search(r["text"]) or _WININI.search(r["text"]):
                return _finding(self, point, payload,
                                "A system file (/etc/passwd or win.ini) was returned — path traversal.", "firm", r)
        return None


class OpenRedirect:
    key, title, severity = "open-redirect", "Open redirect", "medium"

    def run(self, point, build, send, baseline, rand):
        name, val = point["name"].lower(), point.get("value", "")
        if point["loc"] not in ("query", "body-form"):
            return None
        if name not in REDIRECT_NAMES and not (val.startswith(("http://", "https://", "/"))):
            return None
        host = f"wyrm{rand}.example.test"
        for payload in (f"https://{host}/", f"//{host}/"):
            r = send(*build(payload))
            if r and r.get("status") in (301, 302, 303, 307, 308):
                loc = (r.get("location") or "")
                if host in loc:
                    return _finding(self, point, payload,
                                    f"The app redirected (HTTP {r['status']}) to the attacker-controlled host "
                                    f"({loc[:120]}) — open redirect.", "firm", r)
        return None


class CrlfInjection:
    key, title, severity = "crlf", "CRLF / header injection", "medium"

    def run(self, point, build, send, baseline, rand):
        marker = f"wyrm{rand}"
        payload = point.get("value", "") + f"\r\n{marker}: 1"   # raw CRLF; query/form builders url-encode it
        r = send(*build(payload))
        if r and marker.lower() in {k.lower() for k in r.get("headers", {})}:
            return _finding(self, point, payload,
                            f"An injected header ({marker}) appeared in the response — CRLF/header injection.",
                            "firm", r)
        return None


ALL_CHECKS = [ReflectedXSS(), SqlError(), Ssti(), PathTraversal(), OpenRedirect(), CrlfInjection()]
