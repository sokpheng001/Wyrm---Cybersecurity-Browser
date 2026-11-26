#------------------------------------------------------------------------------
# Wyrm — wyrm/security/suggest.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Suggest the next testing tools for the page the user is on.

`suggest_tools(page, result)` reads the passive page info (forms, scripts, iframes…) and the Overview analysis
result (issue categories) and returns a short, ranked list of relevant tools:

    [{"tool": <nav tab name>, "reason": <why>, "priority": int}, …]

Pure/Qt-free so it is unit-testable. Suggestions are hints for *authorized* testing — they never act on their own;
the user picks one, and the tools themselves stay scope-gated."""
from __future__ import annotations


def _categories(result: dict) -> set[str]:
    return {i.get("category", "") for i in (result or {}).get("issues", [])}


def suggest_tools(page: dict, result: dict | None = None, limit: int = 6) -> list[dict]:
    page = page or {}
    result = result or {}
    cats = _categories(result)
    forms = page.get("forms") or []
    has_login = any(f.get("password") for f in forms)
    state_changing = [f for f in forms if (f.get("method") or "get").lower() == "post"]
    csrfless_login = [f for f in forms if f.get("password") and not f.get("csrf")]
    scripts = page.get("scripts") or []
    iframes = int(page.get("iframes") or 0)

    out: list[dict] = []

    def add(tool, reason, priority, sub=""):
        out.append({"tool": tool, "reason": reason, "priority": priority, "sub": sub})

    # --- authentication surface
    if has_login:
        add("Session / auth", "This page has a login form — record a login macro so Wyrm can re-auth automatically.", 10)
        add("Intruder", "Login form present — fuzz/credential-test it (in scope, rate-limited).", 20)
    if csrfless_login:
        add("Scanner", "A password form has no obvious CSRF token — worth checking CSRF/clickjacking protections.", 15)

    # --- forms / parameters → active testing
    if forms:
        add("Audit", f"{len(forms)} form(s) on the page — run an active scan (SQLi/XSS/SSRF…) on their requests.", 30)
    if state_changing:
        add("Tools", "POST form(s) here — capture and replay a request to probe it by hand.", 35, sub="Repeater")

    # --- JavaScript / endpoints / secrets
    if "JavaScript: possible secrets" in cats:
        add("Scanner", "Possible secrets were seen in the page's JavaScript — review with JS recon.", 12, sub="JS recon")
    if "JavaScript: endpoints" in cats or len(scripts) >= 5:
        add("Scanner", f"{len(scripts)} script(s) — pull endpoints/API paths with JS recon.", 40, sub="JS recon")
        add("Site map", "Map the endpoints discovered from the page's scripts and links.", 55)

    # --- transport / headers / cookies
    if "CORS" in cats:
        add("Audit", "A CORS issue was flagged — test cross-origin access controls.", 25)
    if "Cookies" in cats:
        add("Session / auth", "Cookie issues were flagged — inspect session/auth handling.", 45)
    if iframes or "Content-Security-Policy" in cats:
        add("Scanner", "Framing/CSP worth checking — run the clickjacking test.", 50, sub="Clickjacking test")

    # --- always-useful baseline (low priority, so specific hints come first)
    add("Traffic", "Watch every request this site makes.", 80)
    add("Proxy", "Turn on interception to capture full requests/responses with bodies.", 85)

    # de-duplicate by (tool, sub), keeping the highest-priority (lowest number) reason, then sort and cap
    best: dict[tuple, dict] = {}
    for s in out:
        key = (s["tool"], s["sub"])
        if key not in best or s["priority"] < best[key]["priority"]:
            best[key] = s
    ranked = sorted(best.values(), key=lambda s: s["priority"])
    return ranked[:limit]
