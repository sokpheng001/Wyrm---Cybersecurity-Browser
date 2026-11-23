#------------------------------------------------------------------------------
# Wyrm — wyrm/security/discover.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Passive content discovery — strictly NOT brute-forcing.

It reads only resources a site publishes about itself: its robots.txt and its sitemap.xml (following a
sitemap index one level). These are single, well-known requests the site intends to be fetched — there
is no wordlist, no guessing, and no directory/file enumeration. Everything is scope-gated by the caller.
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse

import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Wyrm/1.0"
TIMEOUT = 12
MAX_URLS = 3000


def _session(proxies):
    s = requests.Session()
    s.trust_env = False
    s.headers["User-Agent"] = UA
    return s


def fetch_robots(base: str, proxies=None, verify=True) -> dict:
    """Return {'paths': [...], 'sitemaps': [...]} parsed from robots.txt (Allow/Disallow + Sitemap)."""
    url = urljoin(base, "/robots.txt")
    paths, sitemaps = [], []
    try:
        r = _session(proxies).get(url, timeout=TIMEOUT, proxies=proxies, verify=verify)
        if not r.ok or "text" not in r.headers.get("content-type", "text"):
            return {"paths": [], "sitemaps": [], "ok": False}
        for line in r.text.splitlines():
            line = line.strip()
            low = line.lower()
            if low.startswith(("disallow:", "allow:")):
                p = line.split(":", 1)[1].strip()
                if p and p != "/":
                    paths.append(p.split("*")[0].split("$")[0])
            elif low.startswith("sitemap:"):
                sitemaps.append(line.split(":", 1)[1].strip())
    except requests.RequestException:
        return {"paths": [], "sitemaps": [], "ok": False}
    # dedupe, keep order
    return {"paths": list(dict.fromkeys(p for p in paths if p)),
            "sitemaps": list(dict.fromkeys(sitemaps)), "ok": True}


def fetch_sitemap(url: str, proxies=None, verify=True, _depth=0) -> list[str]:
    """Return all <loc> URLs in a sitemap, following a sitemap index one level deep."""
    if _depth > 1:
        return []
    out: list[str] = []
    try:
        r = _session(proxies).get(url, timeout=TIMEOUT, proxies=proxies, verify=verify)
        if not r.ok:
            return []
        root = ET.fromstring(r.content)
    except (requests.RequestException, ET.ParseError):
        return []
    tag = root.tag.lower()
    ns = "{http://www.sitemaps.org/schemas/sitemap/0.9}"
    if tag.endswith("sitemapindex"):
        for sm in root.findall(f"{ns}sitemap"):
            loc = sm.findtext(f"{ns}loc")
            if loc:
                out += fetch_sitemap(loc.strip(), proxies, verify, _depth + 1)
            if len(out) >= MAX_URLS:
                break
    else:
        for u in root.findall(f"{ns}url"):
            loc = u.findtext(f"{ns}loc")
            if loc:
                out.append(loc.strip())
            if len(out) >= MAX_URLS:
                break
    return out[:MAX_URLS]


def discover(base: str, proxies=None, verify=True) -> dict:
    """Passive discovery for one origin. Returns discovered absolute URLs grouped by source."""
    origin = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    robots = fetch_robots(origin, proxies, verify)
    from_robots = [urljoin(origin + "/", p) for p in robots["paths"]]
    sitemaps = robots["sitemaps"] or [urljoin(origin, "/sitemap.xml")]
    from_sitemap: list[str] = []
    for sm in sitemaps[:5]:
        from_sitemap += fetch_sitemap(sm, proxies, verify)
        if len(from_sitemap) >= MAX_URLS:
            break
    return {
        "origin": origin,
        "robots": list(dict.fromkeys(from_robots)),
        "sitemap": list(dict.fromkeys(from_sitemap)),
        "sitemaps_checked": sitemaps[:5],
        "robots_ok": robots["ok"],
    }
