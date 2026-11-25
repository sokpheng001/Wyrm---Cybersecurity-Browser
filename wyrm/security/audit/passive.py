#------------------------------------------------------------------------------
# Wyrm — wyrm/security/audit/passive.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Passive checks on a single response (no extra requests): missing security headers, weak cookie flags,
version/technology disclosure and verbose errors. Safe to run on any response the proxy already captured."""
from __future__ import annotations

import re

_ERROR_SIG = re.compile(r"Traceback \(most recent call last\)|Fatal error:|Exception in thread|<b>Warning</b>:|"
                        r"ORA-\d{5}|\.java:\d+\)|org\.apache\.|System\.Web\.|Microsoft \.NET Framework", re.I)

# High-signal secret/credential patterns that should never appear in a response body. Kept specific to keep
# false positives low; evidence is always redacted so the finding itself doesn't store the full secret.
_SECRETS = [
    ("AWS access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), "medium"),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"), "high"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), "high"),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), "high"),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{20,}\b"), "high"),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"), "high"),
    ("Hard-coded secret assignment",
     re.compile(r"""(?i)(?:api[_-]?key|secret|token|passwd|password)["']?\s*[:=]\s*["']([0-9A-Za-z/\+\-_]{16,})["']"""),
     "medium"),
]


def _redact(s: str) -> str:
    """Show just enough to recognise a secret without storing it in full."""
    s = s.strip()
    return (s[:4] + "…(" + str(len(s)) + " chars)") if len(s) > 8 else "(redacted)"


def check_response(url: str, resp: dict) -> list[dict]:
    out = []
    H = resp.get("headers", {})     # lower-cased keys
    status = resp.get("status")
    text = resp.get("text", "") or ""
    https = url.lower().startswith("https://")
    ct = str(H.get("content-type", "")).lower()
    html = "text/html" in ct
    csp = str(H.get("content-security-policy", ""))

    def add(title, sev, ev):
        out.append({"check": "passive", "title": title, "severity": sev, "confidence": "certain",
                    "loc": "response", "param": "", "payload": "", "evidence": ev, "status": status, "url": url})

    if html and not csp:
        add("Missing Content-Security-Policy", "low", "No CSP header — the page has no built-in XSS/clickjacking defence.")
    if html and "x-frame-options" not in H and "frame-ancestors" not in csp.lower():
        add("Missing clickjacking protection", "low", "No X-Frame-Options and no CSP frame-ancestors.")
    if "x-content-type-options" not in H:
        add("Missing X-Content-Type-Options: nosniff", "info", "Responses can be MIME-sniffed by the browser.")
    if https and "strict-transport-security" not in H:
        add("Missing HSTS", "low", "No Strict-Transport-Security header on an HTTPS response.")
    srv = str(H.get("server", ""))
    if re.search(r"\d+\.\d+", srv):
        add("Server version disclosure", "info", f"Server: {srv}")
    if H.get("x-powered-by"):
        add("Technology disclosure (X-Powered-By)", "info", f"X-Powered-By: {H.get('x-powered-by')}")
    for c in (resp.get("set_cookie") or []):
        low = c.lower()
        name = c.split("=", 1)[0].strip()
        if https and "secure" not in low:
            add(f"Cookie without Secure flag: {name}", "low", c[:120])
        if "httponly" not in low:
            add(f"Cookie without HttpOnly flag: {name}", "low", c[:120])
    if _ERROR_SIG.search(text):
        add("Verbose error / stack trace", "low", "The response body contains a stack trace or verbose error.")
    seen_secrets = set()
    for name, rx, sev in _SECRETS:
        if name in seen_secrets:
            continue
        m = rx.search(text)
        if m:
            seen_secrets.add(name)
            hit = m.group(1) if (m.groups() and m.group(1)) else (m.group(0) if "PRIVATE KEY" not in m.group(0) else "")
            ev = f"{name} exposed in the response body" + (f": {_redact(hit)}" if hit else ".")
            add(f"Secret exposed: {name}", sev, ev)
    return out
