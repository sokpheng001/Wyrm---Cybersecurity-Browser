#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/toolnav.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Security panel navigation model: how tools are grouped, described and found.

The panel has many tools, some nested (Tools → Repeater, Scanner → nuclei). The nav keeps every group short
(≤ 4 items), lets people pin the tools they use, collapse groups they don't, and search across all tools,
nested ones included. This module has no Qt so it can be unit tested."""
from __future__ import annotations

# Nav groups, top to bottom, following a testing workflow: protect → map → watch traffic → scan → test → report.
GROUPS: list[tuple[str, list[str]]] = [
    ("PROTECTION", ["Shields"]),
    ("RECON", ["Overview", "Site map", "Recon"]),
    ("NETWORK", ["Traffic", "Proxy", "WebSocket", "API & WebSocket"]),
    ("SCANNING", ["Scanner", "Audit", "DOM Analysis", "OOB Interactions"]),
    ("MANUAL", ["Tools", "Intruder", "Workflows", "Session / auth"]),
    ("FINDINGS", ["Findings"]),
    ("ADD-ONS", ["Add-ons"]),   # add-on-provided tabs are appended to this group at runtime
]

PINNED = "PINNED"

# name -> (one-line description shown on hover, extra search keywords)
TOOL_INFO: dict[str, tuple[str, str]] = {
    "Shields": ("What was blocked on this page, and all protection settings",
                "block ads trackers privacy https fingerprint protection"),
    "Overview": ("Passive security grade of the open page: headers, cookies, TLS",
                 "grade headers csp hsts cookies analyze page"),
    "Site map": ("Hosts and paths seen while browsing, page links, robots.txt and sitemap.xml",
                 "tree paths crawl robots sitemap links"),
    "Recon": ("Subdomains (crt.sh), archived URLs (Wayback), well-known files, ProjectDiscovery Chaos",
              "subdomain crt wayback chaos osint bug bounty security.txt"),
    "Traffic": ("Every request the browser makes, filterable, with per-site focus",
                "requests http history log network"),
    "Proxy": ("Full HTTPS history with bodies, and response interception (hold, edit, forward)",
              "mitm intercept history burp forward http2"),
    "WebSocket": ("Live WebSocket frames, with frame editing (hold, edit, forward or drop)",
                  "ws socket frames intercept"),
    "API & WebSocket": ("Live fetch/XHR calls (with bodies) and WebSocket frames captured from pages",
                        "api xhr fetch json graphql capture"),
    "Scanner": ("Technologies, JS recon, port scan, CORS and clickjacking tests, ProjectDiscovery tools",
                "tech wappalyzer js secrets port nmap cors clickjacking nuclei httpx"),
    "Audit": ("Active vulnerability scan of a request or a whole site (SQLi, XSS, SSRF…)",
              "active scan sqli xss ssrf injection vulnerability site"),
    "DOM Analysis": ("Passive DOM-XSS source and sink scan of the open page",
                     "dom xss sink source javascript"),
    "OOB Interactions": ("Callback listener with unique payload URLs for blind bugs",
                         "oob out-of-band collaborator interactsh dns blind callback"),
    "Tools": ("Repeater, Decoder, JWT, Hash, Match & Replace, Comparer, Sequencer, AI Triage",
              "repeater decoder jwt hash utilities"),
    "Intruder": ("Scope-gated, rate-limited payload testing of one request",
                 "fuzz brute payload wordlist attack"),
    "Workflows": ("Automation pipelines that run on live proxy traffic",
                  "automation pipeline macro rules"),
    "Session / auth": ("Login macro with automatic re-login when the session expires",
                       "session login auth cookie token macro"),
    "Findings": ("Engagement findings and report export",
                 "report issues vulnerabilities export"),
    "Add-ons": ("Install, enable or disable and inspect Wyrm add-ons",
                "extensions plugins addons"),
}

# Tools nested inside a tab: tab -> {sub-tool name: (description, keywords)}
SUBTOOLS: dict[str, dict[str, tuple[str, str]]] = {
    "Tools": {
        "Decoder": ("Encode and decode Base64, URL, hex, HTML and more", "encode decode base64 url hex html"),
        "JWT": ("Decode a JSON Web Token and check its signature setup", "jwt token json web token"),
        "Hash": ("Hash text with MD5, SHA-1, SHA-256 and more", "hash md5 sha digest"),
        "Repeater": ("Edit and resend one HTTP request", "resend request http edit send curl"),
        "Match & Replace": ("Rewrite requests and responses on the fly", "rewrite rules replace header"),
        "Comparer": ("Diff two requests or responses", "diff compare"),
        "Sequencer": ("Measure how random session tokens are", "random entropy token"),
        "AI Triage": ("AI-assisted review of a request (scope-gated, you approve)", "ai llm triage"),
    },
}


def entry(label: str, tab: str, sub: str = "", desc: str = "", keys: str = "") -> dict:
    return {"label": label, "tab": tab, "sub": sub, "desc": desc,
            "hay": " ".join((label, tab, desc, keys)).lower()}


def base_entries(tab_names) -> list[dict]:
    """One entry per tab plus one per nested sub-tool (only for tabs that exist)."""
    names = list(tab_names)
    out = []
    for n in names:
        desc, keys = TOOL_INFO.get(n, ("", ""))
        out.append(entry(n, n, "", desc, keys))
    for tab, subs in SUBTOOLS.items():
        if tab in names:
            for s, (desc, keys) in subs.items():
                out.append(entry(s, tab, s, desc, keys))
    return out


def search(entries: list[dict], query: str, limit: int = 30) -> list[dict]:
    """Entries whose text contains every word of `query`, best first: label prefix, then label word, then
    anywhere in the description or keywords. Ties keep their original order."""
    words = query.lower().split()
    if not words:
        return []
    ranked = []
    for i, e in enumerate(entries):
        if not all(w in e["hay"] for w in words):
            continue
        lab = e["label"].lower()
        if lab.startswith(words[0]):
            score = 0
        elif any(part.startswith(words[0]) for part in lab.replace("/", " ").split()):
            score = 1
        elif all(w in lab for w in words):
            score = 2
        else:
            score = 3
        ranked.append((score, i, e))
    ranked.sort(key=lambda t: (t[0], t[1]))
    return [e for _s, _i, e in ranked[:limit]]


def sections(groups, pinned, collapsed=()) -> list[tuple[str, list[str], bool]]:
    """What the nav shows, in order: (caption, item names, collapsed?). Pinned tools move into a PINNED group
    at the top (only when there are any); empty groups are dropped."""
    names = {n for _t, items in groups for n in items}
    pins = [n for n in pinned if n in names]
    out = [(PINNED, pins, PINNED in collapsed)] if pins else []
    for title, items in groups:
        rest = [n for n in items if n not in pins]
        if rest:
            out.append((title, rest, title in collapsed))
    return out
