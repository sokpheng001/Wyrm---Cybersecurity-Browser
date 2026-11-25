#------------------------------------------------------------------------------
# Wyrm — wyrm/browser/capturemsg.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Strict validation of capture.js sentinel messages (F1).

capture.js runs in the page's own JS world, so whatever it reports is *page-reported* data: even with every
built-in pinned, a hostile page fully controls its own URLs and bodies. This module therefore accepts only a
fixed schema — known kinds/events, a sane status and method, bounded strings, at most 64 headers — drops every
unknown key, and ignores the `page` value the script claims in favour of the frame URL Qt itself reports.
Pure Python (no Qt) so it is unit-testable.
"""
from __future__ import annotations

import json
import re

KINDS = frozenset({"fetch", "xhr", "ws"})
WS_EVENTS = frozenset({"open", "send", "recv", "close"})
_METHOD = re.compile(r"^[A-Z]{1,16}$")
MAX_URL = 4096
MAX_BODY = 12_000 + 32          # capture.js caps bodies at 12000 chars + a "…[truncated]" marker
MAX_ERROR = 300
MAX_HEADERS = 64
MAX_HEADER_NAME = 256
MAX_HEADER_VALUE = 4096
MAX_PAYLOAD = 200_000           # whole JSON message; anything bigger is rejected unparsed
SOURCE = "page-reported"        # shown in the UI; proxy rows are the trusted source


def _s(v, limit: int) -> str | None:
    """A bounded string, or None if the value isn't a string at all or is too long."""
    if not isinstance(v, str) or len(v) > limit:
        return None
    return v


def parse(payload: str, page_url: str = "") -> dict | None:
    """Validate one sentinel payload. Returns a clean record or None (reject). `page_url` is the frame/page URL
    reported by Qt (QWebEnginePage.url()), which replaces anything the script says about where it ran."""
    if not isinstance(payload, str) or len(payload) > MAX_PAYLOAD:
        return None
    try:
        raw = json.loads(payload)
    except ValueError:
        return None
    if not isinstance(raw, dict):
        return None
    k = raw.get("k")
    if k not in KINDS:
        return None
    url = _s(raw.get("url", ""), MAX_URL)
    if url is None:
        return None
    out = {"k": k, "url": url, "page": str(page_url)[:MAX_URL], "source": SOURCE}
    t = raw.get("t")
    if isinstance(t, (int, float)) and not isinstance(t, bool) and 0 <= t < 1e14:
        out["t"] = int(t)

    if k == "ws":
        ev = raw.get("ev")
        if ev not in WS_EVENTS:
            return None
        out["ev"] = ev
        for key in ("req", "res"):
            if key in raw:
                v = _s(raw[key], MAX_BODY)
                if v is None:
                    return None
                out[key] = v
        return out

    method = raw.get("method", "GET")
    if not isinstance(method, str) or not _METHOD.match(method):
        return None
    status = raw.get("status", 0)
    if isinstance(status, bool) or not isinstance(status, int) or not 0 <= status <= 999:
        return None
    out["method"] = method
    out["status"] = status
    for key, limit in (("req", MAX_BODY), ("res", MAX_BODY), ("error", MAX_ERROR)):
        if key in raw:
            v = _s(raw[key], limit)
            if v is None:
                return None
            out[key] = v
    hdrs = raw.get("headers")
    if hdrs is not None:
        if not isinstance(hdrs, dict) or len(hdrs) > MAX_HEADERS:
            return None
        clean = {}
        for hk, hv in hdrs.items():
            if (not isinstance(hk, str) or not isinstance(hv, str) or not hk
                    or len(hk) > MAX_HEADER_NAME or len(hv) > MAX_HEADER_VALUE):
                return None
            clean[hk] = hv
        out["headers"] = clean
    return out
