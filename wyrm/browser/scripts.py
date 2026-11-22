#------------------------------------------------------------------------------
# Wyrm — wyrm/browser/scripts.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""JavaScript injected into pages (CiteSee, YouTube ad removal, anti-fingerprinting, collectors)."""
from __future__ import annotations

from pathlib import Path


CITESEE_JS = (Path(__file__).parent.parent / "citesee.js").read_text(encoding="utf-8")


YOUTUBE_JS = (Path(__file__).parent.parent / "youtube.js").read_text(encoding="utf-8")


FINGERPRINT_JS = (Path(__file__).parent.parent / "fingerprint.js").read_text(encoding="utf-8")

CAPTURE_JS = (Path(__file__).parent.parent / "capture.js").read_text(encoding="utf-8")


COLLECT_JS = """JSON.stringify((function(){const c=new Set(),i=new Set();
document.querySelectorAll('[class],[id]').forEach((e,n)=>{if(n>4000)return;
if(e.id)i.add(e.id);if(typeof e.className==='string')e.className.split(/\\s+/).forEach(x=>x&&c.add(x));});
return {classes:[...c].slice(0,3000),ids:[...i].slice(0,3000),yt:window.__hbYtCount||0};})())"""
