#------------------------------------------------------------------------------
# Wyrm — wyrm/browser/scripts.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""JavaScript injected into pages (CiteSee, YouTube ad removal, anti-fingerprinting, collectors)."""
from __future__ import annotations

import secrets
from pathlib import Path


def _load(name: str) -> str:
    """Read an injected script that ships beside the package. Degrade gracefully (empty = feature no-ops) rather
    than crash the whole browser at startup if a file is missing from a build — this runs at import time."""
    try:
        return (Path(__file__).parent.parent / name).read_text(encoding="utf-8")
    except OSError:
        return ""


CITESEE_JS = _load("citesee.js")

YOUTUBE_JS = _load("youtube.js")

FINGERPRINT_JS = _load("fingerprint.js")

# Per-process random secret so a page can't forge capture rows (SEC-4): the sentinel console.debug line that
# Wyrm listens for carries this token, which pages can neither read (we emit via the original console.debug) nor
# guess. _CAP_PREFIX in the page object is derived from the same token.
CAP_TOKEN = secrets.token_hex(16)
CAP_PREFIX = "[[WYRMCAP:" + CAP_TOKEN + "]]"
CAPTURE_JS = _load("capture.js").replace("__WYRM_CAP_TOKEN__", CAP_TOKEN)


COLLECT_JS = """JSON.stringify((function(){const c=new Set(),i=new Set();
document.querySelectorAll('[class],[id]').forEach((e,n)=>{if(n>4000)return;
if(e.id)i.add(e.id);if(typeof e.className==='string')e.className.split(/\\s+/).forEach(x=>x&&c.add(x));});
return {classes:[...c].slice(0,3000),ids:[...i].slice(0,3000),yt:window.__hbYtCount||0};})())"""
