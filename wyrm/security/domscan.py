#------------------------------------------------------------------------------
# Wyrm — wyrm/security/domscan.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Passive DOM security analysis — a static source/sink scanner inspired by DOM Invader.

Read-only: it scans the inline scripts the page already contains plus the same-scope external
scripts it already loads, looking for DOM-XSS *sources* (attacker-influenceable inputs) and *sinks*
(APIs that turn strings into markup or code). It classifies each hit, captures an evidence snippet,
and flags scripts that contain BOTH a source and a dangerous sink as a potential DOM-XSS data-flow
worth manual review. It never executes payloads, never exploits, and never modifies the page.

This is a heuristic static scan, not taint tracking, so results are *potential* findings for a human
to verify — exactly how DOM Invader's own observations are meant to be used.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

import requests

from . import analyzer  # reuse issue() and the UA/TIMEOUT conventions

UA = analyzer.UA
TIMEOUT = analyzer.TIMEOUT

# (name, compiled regex) — attacker-influenceable inputs
SOURCES: list[tuple[str, re.Pattern]] = [
    ("location.href", re.compile(r"\blocation\s*\.\s*href\b")),
    ("location.search", re.compile(r"\blocation\s*\.\s*search\b")),
    ("location.hash", re.compile(r"\blocation\s*\.\s*hash\b")),
    ("location.pathname", re.compile(r"\blocation\s*\.\s*pathname\b")),
    ("document.URL", re.compile(r"\bdocument\s*\.\s*(URL|documentURI|baseURI)\b")),
    ("document.referrer", re.compile(r"\bdocument\s*\.\s*referrer\b")),
    ("document.cookie", re.compile(r"\bdocument\s*\.\s*cookie\b")),
    ("window.name", re.compile(r"\bwindow\s*\.\s*name\b")),
    ("postMessage listener", re.compile(r"addEventListener\s*\(\s*['\"]message['\"]|\bonmessage\s*=")),
    ("URLSearchParams", re.compile(r"\bURLSearchParams\b|\.searchParams\b")),
    ("localStorage", re.compile(r"\blocalStorage\s*\.\s*getItem|\blocalStorage\s*\[")),
    ("sessionStorage", re.compile(r"\bsessionStorage\s*\.\s*getItem|\bsessionStorage\s*\[")),
]

# (name, compiled regex, severity) — APIs that render strings as HTML/JS
SINKS: list[tuple[str, re.Pattern, str]] = [
    ("eval()", re.compile(r"\beval\s*\("), "high"),
    ("new Function()", re.compile(r"\bnew\s+Function\s*\("), "high"),
    ("element.innerHTML =", re.compile(r"\.innerHTML\s*="), "high"),
    ("element.outerHTML =", re.compile(r"\.outerHTML\s*="), "high"),
    ("insertAdjacentHTML()", re.compile(r"\.insertAdjacentHTML\s*\("), "high"),
    ("document.write()", re.compile(r"\bdocument\s*\.\s*write(?:ln)?\s*\("), "high"),
    ("setTimeout(string)", re.compile(r"\bsetTimeout\s*\(\s*['\"]"), "medium"),
    ("setInterval(string)", re.compile(r"\bsetInterval\s*\(\s*['\"]"), "medium"),
    ("jQuery .html()", re.compile(r"\.html\s*\("), "medium"),
    ("jQuery DOM insert", re.compile(r"\.(?:append|prepend|after|before|replaceWith|wrap)\s*\("), "low"),
    ("location assignment", re.compile(r"\blocation\s*\.\s*(?:assign|replace)\s*\(|\blocation\s*=\s*[^=]"), "medium"),
    (".src/.href assignment", re.compile(r"\.(?:src|href)\s*=\s*[^=]"), "low"),
    ("document.domain =", re.compile(r"\bdocument\s*\.\s*domain\s*="), "medium"),
    ("jQuery $.globalEval", re.compile(r"\$\s*\.\s*globalEval\s*\("), "high"),
]

_SEV = {"high": 1, "medium": 2, "low": 3, "info": 4}


def _snippet(text: str, start: int, end: int) -> tuple[str, int]:
    line = text.count("\n", 0, start) + 1
    ctx = text[max(0, start - 50): end + 50].replace("\n", " ").strip()
    return (ctx[:200], line)


def _collect_scripts(page: dict, in_scope, proxies, verify, max_files: int) -> list[tuple[str, str]]:
    out = [("inline #%d" % i, t) for i, t in enumerate(page.get("inline", []))]
    fetched = 0
    sess = requests.Session()
    sess.trust_env = False
    for src in page.get("scripts", []):
        host = urlparse(src).hostname or ""
        if fetched >= max_files or (in_scope is not None and not in_scope(host)):
            continue
        try:
            r = sess.get(src, headers={"User-Agent": UA}, timeout=TIMEOUT, proxies=proxies, verify=verify)
            if r.ok and len(r.content) < 6_000_000:
                out.append((src, r.text))
                fetched += 1
        except requests.RequestException:
            continue
    return out


def analyze_dom(page: dict, in_scope=None, proxies=None, verify=True, max_files: int = 25) -> dict:
    """Scan the page's scripts for DOM sources/sinks. Returns issues + per-script flow flags + counts."""
    scripts = _collect_scripts(page, in_scope, proxies, verify, max_files)
    issues: list[dict] = []
    per_script_sources: dict[str, set] = {}
    per_script_sinks: dict[str, list] = {}

    for where, text in scripts:
        if not text:
            continue
        for name, rx in SOURCES:
            m = rx.search(text)
            if m:
                ctx, line = _snippet(text, m.start(), m.end())
                issues.append(analyzer.issue("DOM sources", f"Source: {name}", "info",
                                             f"Attacker-influenceable input read in {where} (line {line}). "
                                             "On its own this is not a vulnerability — it matters only if it reaches a sink.",
                                             ctx, where=where, line=line, kind="source"))
                per_script_sources.setdefault(where, set()).add(name)
        for name, rx, sev in SINKS:
            seen_lines = set()
            for m in rx.finditer(text):
                ctx, line = _snippet(text, m.start(), m.end())
                if line in seen_lines:
                    continue
                seen_lines.add(line)
                issues.append(analyzer.issue("DOM sinks", f"Sink: {name}", sev,
                                             f"Dangerous sink in {where} (line {line}). Verify whether any "
                                             "attacker-controlled source reaches it before reporting.",
                                             ctx, where=where, line=line, kind="sink"))
                per_script_sinks.setdefault(where, []).append((name, sev, line))
                if len(seen_lines) >= 25:
                    break

    # data-flow heuristic: a script holding BOTH a source and a dangerous sink is worth manual review
    for where, srcs in per_script_sources.items():
        sinks = per_script_sinks.get(where)
        if not sinks:
            continue
        worst = min(sinks, key=lambda s: _SEV.get(s[1], 9))
        sev = "high" if worst[1] == "high" else "medium"
        issues.append(analyzer.issue(
            "DOM potential flow", f"Potential DOM-XSS flow in {where}", sev,
            f"This script reads attacker-influenceable source(s) [{', '.join(sorted(srcs))}] AND uses "
            f"dangerous sink(s) [{', '.join(sorted({s[0] for s in sinks}))}]. This is a heuristic — manually "
            "confirm the source actually flows into the sink before treating it as a finding.",
            f"Sources: {', '.join(sorted(srcs))}\nSinks: {', '.join(sorted({s[0] for s in sinks}))}",
            where=where, kind="flow"))

    issues.sort(key=lambda i: _SEV.get(i["severity"], 9))
    counts = {
        "sources": sum(1 for i in issues if i.get("kind") == "source"),
        "sinks": sum(1 for i in issues if i.get("kind") == "sink"),
        "flows": sum(1 for i in issues if i.get("kind") == "flow"),
        "scripts": len(scripts),
    }
    return {"issues": issues, "counts": counts}
