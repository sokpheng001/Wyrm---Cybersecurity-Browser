#------------------------------------------------------------------------------
# Wyrm — wyrm/browser/scripts.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""JavaScript injected into pages (CiteSee, YouTube ad removal, anti-fingerprinting, collectors)."""
from __future__ import annotations

import json
import secrets
import sys
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

# --- anti-fingerprinting (F2) ---------------------------------------------------------------------------
# One seed per browser session (process), shared by every frame and document, so a page and its iframes see
# the same values. Chosen here, never derived from anything page-visible.
FP_SEED = secrets.randbelow(2**31 - 2) + 1

# WebGL UNMASKED_VENDOR/RENDERER pairs that real Chrome reports on each OS. They must match the platform in the
# user agent: a macOS UA with a Direct3D renderer exists only in spoofing browsers and singles the user out.
_GPU_PROFILES = {
    "darwin": [
        ("Google Inc. (Apple)", "ANGLE (Apple, ANGLE Metal Renderer: Apple M1, Unspecified Version)"),
        ("Google Inc. (Apple)", "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)"),
        ("Google Inc. (Apple)", "ANGLE (Apple, ANGLE Metal Renderer: Apple M3, Unspecified Version)"),
    ],
    "win32": [
        ("Google Inc. (Intel)", "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (NVIDIA)", "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0, D3D11)"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"),
    ],
    "linux": [
        ("Google Inc. (Intel)", "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)"),
        ("Google Inc. (AMD)", "ANGLE (AMD, AMD Radeon Graphics (radeonsi, renoir, LLVM 15.0.7), OpenGL 4.6)"),
    ],
}
_CORES = {"darwin": [8, 10, 12], "win32": [4, 8, 12, 16], "linux": [4, 8, 12, 16]}


def _os_key(platform: str) -> str:
    if platform.startswith("darwin"):
        return "darwin"
    if platform.startswith(("win", "cygwin", "msys")):
        return "win32"
    return "linux"


def fingerprint_config(platform: str | None = None, seed: int | None = None) -> dict:
    """The per-session values substituted into fingerprint.js for `platform` (default: this OS)."""
    key = _os_key(platform or sys.platform)
    seed = FP_SEED if seed is None else int(seed)
    vendor, renderer = _GPU_PROFILES[key][seed % len(_GPU_PROFILES[key])]
    return {"seed": seed, "vendor": vendor, "renderer": renderer, "cores": _CORES[key], "memory": [4, 8]}


def fingerprint_js(platform: str | None = None, seed: int | None = None) -> str:
    cfg = json.dumps(fingerprint_config(platform, seed))
    return _load("fingerprint.js").replace("/*__WYRM_FP_CONFIG__*/null", cfg)


FINGERPRINT_JS = fingerprint_js()

# Per-process random secret so a page can't forge capture rows (SEC-4): the sentinel console.debug line that
# Wyrm listens for carries this token, which pages can neither read (we emit via the original console.debug) nor
# guess. _CAP_PREFIX in the page object is derived from the same token.
CAP_TOKEN = secrets.token_hex(16)
CAP_PREFIX = "[[WYRMCAP:" + CAP_TOKEN + "]]"
CAPTURE_JS = _load("capture.js").replace("__WYRM_CAP_TOKEN__", CAP_TOKEN)

# B2: document-start hook that counts postMessage listeners; pageinfo.js reads it via this secret event type.
HOOK_TOKEN = "wyrm-" + secrets.token_hex(12)
PAGEHOOK_JS = _load("security/pagehook.js").replace("__WYRM_HOOK_TOKEN__", HOOK_TOKEN)
PAGEINFO_JS = _load("security/pageinfo.js").replace("__WYRM_HOOK_TOKEN__", HOOK_TOKEN)


COLLECT_JS = """JSON.stringify((function(){const c=new Set(),i=new Set();
document.querySelectorAll('[class],[id]').forEach((e,n)=>{if(n>4000)return;
if(e.id)i.add(e.id);if(typeof e.className==='string')e.className.split(/\\s+/).forEach(x=>x&&c.add(x));});
return {classes:[...c].slice(0,3000),ids:[...i].slice(0,3000),yt:window.__hbYtCount||0};})())"""
