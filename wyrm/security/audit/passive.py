#------------------------------------------------------------------------------
# Wyrm — wyrm/security/audit/passive.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Passive checks on a single response (no extra requests): missing security headers, weak cookie flags,
version/technology disclosure and verbose errors. Safe to run on any response the proxy already captured."""
from __future__ import annotations

import base64
import json
import re

_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")

# Interactive debuggers / framework debug pages that leak source, config or even allow code execution.
_DEBUG_SIG = [
    ("Werkzeug interactive debugger exposed", "high",
     re.compile(r"Werkzeug Debugger|werkzeug\.debug|__traceback_hide__|The debugger caught an exception")),
    ("Django debug page (DEBUG=True)", "high",
     re.compile(r"you have\s+DEBUG\s*=\s*True|<div[^>]*id=\"?traceback|Django Version:", re.I)),
    ("Rails detailed exception page", "high", re.compile(r"Action Controller: Exception caught|rails\.png")),
    ("phpinfo() output exposed", "medium",
     re.compile(r"<title>phpinfo\(\)</title>|>phpinfo\(\)<|PHP Version\s*</td>|HTTP Request Headers.*PHP Credits", re.S)),
]


def _b64url_json(seg: str):
    seg += "=" * (-len(seg) % 4)
    return json.loads(base64.urlsafe_b64decode(seg.encode("ascii")))

_ERROR_SIG = re.compile(r"Traceback \(most recent call last\)|Fatal error:|Exception in thread|<b>Warning</b>:|"
                        r"ORA-\d{5}|\.java:\d+\)|org\.apache\.|System\.Web\.|Microsoft \.NET Framework", re.I)

# High-signal secret/credential patterns that should never appear in a response body. Kept specific to keep
# false positives low; evidence is always redacted so the finding itself doesn't store the full secret.
def _redact(s: str) -> str:
    """Show just enough to recognise a secret without storing it in full."""
    s = s.strip()
    return (s[:4] + "…(" + str(len(s)) + " chars)") if len(s) > 8 else "(redacted)"


# Brand-prefixed card patterns (Visa/Mastercard/Amex/Discover) keep false positives low; Luhn confirms.
_CC_RE = re.compile(r"(?<!\d)(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})(?!\d)")


def _luhn(num: str) -> bool:
    digits = [int(c) for c in num]
    checksum = sum(digits[-1::-2]) + sum(sum(divmod(d * 2, 10)) for d in digits[-2::-2])
    return checksum % 10 == 0


def _mask_pan(pan: str) -> str:
    return pan[:6] + "*" * (len(pan) - 10) + pan[-4:] if len(pan) >= 10 else "****"


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

    from .. import severity as _sev   # QA-M1: shared default severities so all tools agree
    if html and not csp:
        add("Missing Content-Security-Policy", _sev.default("missing-csp"),
            "No CSP header — the page has no built-in XSS/clickjacking defence.")
    if html and "x-frame-options" not in H and "frame-ancestors" not in csp.lower():
        add("Missing clickjacking protection", _sev.default("missing-clickjacking"),
            "No X-Frame-Options and no CSP frame-ancestors.")
    if "x-content-type-options" not in H:
        add("Missing X-Content-Type-Options: nosniff", _sev.default("missing-nosniff"),
            "Responses can be MIME-sniffed by the browser.")
    if https and "strict-transport-security" not in H:
        add("Missing HSTS", _sev.default("missing-hsts"), "No Strict-Transport-Security header on an HTTPS response.")
    srv = str(H.get("server", ""))
    if re.search(r"\d+\.\d+", srv):
        add("Server version disclosure", _sev.default("server-version"), f"Server: {srv}")
    if H.get("x-powered-by"):
        add("Technology disclosure (X-Powered-By)", _sev.default("powered-by"), f"X-Powered-By: {H.get('x-powered-by')}")
    for c in (resp.get("set_cookie") or []):
        low = c.lower()
        name = c.split("=", 1)[0].strip()
        if https and "secure" not in low:
            add(f"Cookie without Secure flag: {name}", _sev.default("cookie-no-secure"), c[:120])
        if "httponly" not in low:
            add(f"Cookie without HttpOnly flag: {name}", _sev.default("cookie-no-httponly"), c[:120])
    if _ERROR_SIG.search(text):
        add("Verbose error / stack trace", "low", "The response body contains a stack trace or verbose error.")
    for name, sev, rx in _DEBUG_SIG:
        if rx.search(text):
            add(name, sev, "An interactive debugger or framework debug page is exposed — it can leak source, "
                           "configuration and secrets (and some allow code execution). Disable debug mode in "
                           "production.")
            break
    for m in _JWT_RE.finditer(text):
        try:
            hdr = _b64url_json(m.group(0).split(".")[0])
            payload = _b64url_json(m.group(0).split(".")[1])
        except Exception:  # noqa: BLE001 - malformed / not actually a JWT; skip
            continue
        if str(hdr.get("alg", "")).lower() == "none":
            add("Unsigned JWT (alg:none) exposed", "high",
                "A JSON Web Token using alg=none (no signature) was found in the response — if the server accepts "
                "these, tokens can be forged.")
            break
        if isinstance(payload, dict) and "exp" not in payload:
            add("JWT without an expiry (exp) exposed", "low",
                f"A JWT (alg={hdr.get('alg')}) has no 'exp' claim — it never expires, so a leaked token stays "
                "valid indefinitely.")
            break
    if html:
        for form in re.findall(r"<form\b[^>]*>.*?</form>", text, re.I | re.S)[:40]:
            if not re.search(r"method\s*=\s*['\"]?\s*post", form, re.I):
                continue   # only state-changing (POST) forms matter for CSRF
            token = re.search(r"<input\b[^>]*\b(?:csrf|token|authenticity|nonce|__requestverification)[^>]*>", form, re.I)
            if not token:
                add("Form without anti-CSRF token", "low",
                    "A POST form has no hidden anti-CSRF token field — verify the endpoint is protected by a "
                    "CSRF token or SameSite cookies before relying on it.")
                break
    if https and html:
        active = re.findall(r"<(?:script|iframe|link|object|embed)\b[^>]*\b(?:src|href|data)\s*=\s*['\"]http://[^'\"]+",
                            text, re.I)
        if active:
            ex = re.search(r"http://[^'\"]+", active[0])
            add("Mixed content (active HTTP resource on an HTTPS page)", "medium",
                f"{len(active)} active resource(s) (script/iframe/…) loaded over http:// — "
                f"e.g. {ex.group(0)[:120] if ex else ''}. These can be tampered with in transit.")
    for m in _CC_RE.finditer(text):
        pan = m.group(0)
        if _luhn(pan):
            add("Cardholder data (PAN) in response", "high",
                f"A Luhn-valid payment card number appears in the response: {_mask_pan(pan)} (PCI-DSS).")
            break   # one is enough to flag
    from .. import secrets as _secrets   # QA-H4: one shared detector, so all tools agree on names + severities
    seen_secrets = set()
    for name, matched, sev, _s, _e in _secrets.find_secrets(text):
        if name in seen_secrets:
            continue
        seen_secrets.add(name)
        hit = "" if name == "Private key block" else matched
        ev = f"{name} exposed in the response body" + (f": {_redact(hit)}" if hit else ".")
        add(f"Secret exposed: {name}", sev, ev)
    return out
