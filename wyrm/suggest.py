#------------------------------------------------------------------------------
# Wyrm — wyrm/suggest.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Live search suggestions for the address bar.

Uses DuckDuckGo's autocomplete endpoint, which does not profile or track the user, so the
privacy posture of the browser is preserved. Only the text the user is already typing to search
is sent — never any identifier. Requests honor the window's proxy settings (so a proxied or Tor
window keeps suggestions on the same anonymized path), and failures are swallowed silently so the
address bar always stays responsive.
"""
from __future__ import annotations

import requests

_ENDPOINT = "https://duckduckgo.com/ac/"


def fetch(query: str, proxies: dict | None = None) -> list[str]:
    query = (query or "").strip()
    if len(query) < 2:
        return []
    try:
        r = requests.get(_ENDPOINT, params={"q": query, "type": "list"},
                         proxies=proxies or None, timeout=4,
                         headers={"User-Agent": "Wyrm/1.0 (+search-suggest)"})
        r.raise_for_status()
        data = r.json()
    except Exception:  # noqa: BLE001 - suggestions are best-effort; never block typing
        return []
    # DuckDuckGo returns either [query, [suggestions]] or [{"phrase": ...}, ...]
    out: list[str] = []
    if isinstance(data, list) and len(data) == 2 and isinstance(data[1], list):
        out = [s for s in data[1] if isinstance(s, str)]
    elif isinstance(data, list):
        out = [d["phrase"] for d in data if isinstance(d, dict) and "phrase" in d]
    seen, uniq = set(), []
    for s in out:
        if s and s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq[:8]
