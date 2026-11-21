#------------------------------------------------------------------------------
# Wyrm — wyrm/security/webchecks.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Developer: @kwan (CORS and clickjacking testers)
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Web security checks based on published research (for AUTHORIZED, in-scope targets).

CORS misconfiguration test — after Chen et al., "We Still Don't Have Secure Cross-Domain Requests: an
Empirical Study of CORS", USENIX Security 2018. Sends a handful of ordinary GET requests with crafted
Origin headers (arbitrary origin, null, prefix/suffix look-alikes, subdomain, plain-HTTP) and reports any
origin the server trusts, especially together with Access-Control-Allow-Credentials: true.

Clickjacking test — after Huang et al., "Clickjacking: Attacks and Defenses", USENIX Security 2012.
Checks whether the page may be framed by other sites (X-Frame-Options / CSP frame-ancestors); the UI can
then open a local proof-of-concept page that frames it.
"""
from __future__ import annotations

from urllib.parse import urlparse

import requests

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Wyrm/1.0 (authorized security test)"}
TIMEOUT = 15
CORS_PAPER = "Chen et al., USENIX Security 2018"
CLICKJACKING_PAPER = "Huang et al., USENIX Security 2012"


def _get(url, headers=None, proxies=None, verify=True):
    return requests.get(url, headers={**UA, **(headers or {})}, timeout=TIMEOUT, allow_redirects=False,
                        proxies=proxies, verify=verify)


def cors_test(url: str, proxies=None, verify=True) -> dict:
    host = urlparse(url).hostname or ""
    scheme = urlparse(url).scheme or "https"
    probes = [  # (label, Origin, severity if trusted)
        ("Arbitrary origin reflected", "https://wyrm-cors-test.example", "high"),
        ("'null' origin trusted (sandboxed iframes, data: URLs)", "null", "high"),
        ("Suffix look-alike trusted (attacker registers <host>.evil)", f"https://{host}.wyrm-test.example", "high"),
        ("Prefix look-alike trusted (attacker registers evil<host>)", f"https://wyrmtest{host}", "high"),
        ("Any subdomain trusted (one XSS on a subdomain is enough)", f"https://wyrm-test.{host}", "medium"),
        ("Plain-HTTP origin trusted (network attacker can inject)", f"http://{host}", "medium"),
    ]
    findings, checked = [], []
    for label, origin, sev in probes:
        try:
            r = _get(url, {"Origin": origin}, proxies, verify)
        except requests.RequestException as e:
            checked.append({"origin": origin, "error": str(e)})
            continue
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        creds = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        checked.append({"origin": origin, "status": r.status_code, "acao": acao, "credentials": creds})
        if acao == origin or (origin == "null" and acao == "null"):
            findings.append({"title": label, "origin": origin, "acao": acao, "credentials": creds,
                             "severity": sev if creds else ("medium" if sev == "high" else "low"),
                             "detail": ("Trusted WITH credentials: another site can read authenticated responses."
                                        if creds else "Trusted without credentials: public data only, but the "
                                                      "policy is too loose.")})
        elif acao == "*" and creds:
            findings.append({"title": "Wildcard with credentials", "origin": origin, "acao": acao, "credentials": True,
                             "severity": "low", "detail": "Browsers reject this combination, but it shows a "
                                                          "misunderstood CORS policy."})
    return {"url": url, "findings": findings, "checked": checked, "paper": CORS_PAPER}


def clickjacking_test(url: str, proxies=None, verify=True) -> dict:
    r = _get(url, proxies=proxies, verify=verify)
    xfo = r.headers.get("X-Frame-Options", "").strip()
    csp = r.headers.get("Content-Security-Policy", "")
    fa = next((d.strip() for d in csp.split(";") if d.strip().lower().startswith("frame-ancestors")), "")
    protected = bool(fa) and "*" not in fa.split()[1:] or xfo.upper() in ("DENY", "SAMEORIGIN")
    if fa and ("'none'" in fa or "'self'" in fa) or xfo.upper() in ("DENY", "SAMEORIGIN"):
        verdict, sev = "Protected: other sites cannot frame this page.", "info"
    elif fa:
        verdict, sev = "Partly protected: frame-ancestors allows some other origins — check they are trusted.", "low"
    else:
        verdict, sev = ("Vulnerable: no X-Frame-Options or CSP frame-ancestors, so any site can frame this page "
                        "and trick users into clicking (clickjacking)."), "medium"
    return {"url": url, "status": r.status_code, "x_frame_options": xfo, "frame_ancestors": fa,
            "protected": protected and sev != "medium", "verdict": verdict, "severity": sev,
            "paper": CLICKJACKING_PAPER}
