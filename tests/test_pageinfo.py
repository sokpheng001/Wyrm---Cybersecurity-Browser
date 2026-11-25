#------------------------------------------------------------------------------
# Wyrm — tests/test_pageinfo.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""B2: page info sees postMessage handlers added with addEventListener("message"), and a page that replaced
JSON.stringify / added toJSON can't rewrite the snapshot. Runs in a real QtWebEngine tab on 127.0.0.1."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wyrm.browser.scripts import PAGEHOOK_JS, PAGEINFO_JS  # noqa: E402
from wyrm.security import domscan  # noqa: E402

SITE = Path(__file__).resolve().parent / "pageinfo"


def _snapshot(scripts):
    pytest.importorskip("PySide6.QtWebEngineCore")
    from webharness import run_page
    out = {}
    msgs = run_page(SITE, "index.html", scripts, eval_js=PAGEINFO_JS, result=out)
    import json
    raw = out.get("value")
    try:
        return json.loads(raw), msgs
    except (TypeError, ValueError):
        return raw, msgs


def test_listener_count_and_untampered_snapshot():
    snap, msgs = _snapshot([("wyrm-pagehook", PAGEHOOK_JS)])
    assert isinstance(snap, dict), snap
    assert snap["url"].startswith("http://127.0.0.1:")              # not the page's forged JSON / toJSON
    assert "inline" in snap and "globals" in snap and snap.get("url") not in ("FORGED", "FORGED2")
    assert snap["postMessageListeners"] == 3 and snap["postMessage"] is True
    assert "NATIVE true" in msgs                    # the hook doesn't stand out to the page


def test_domscan_reports_runtime_listeners():
    snap, _ = _snapshot([("wyrm-pagehook", PAGEHOOK_JS)])
    snap["inline"], snap["scripts"] = [], []
    issues = domscan.analyze_dom(snap)["issues"]
    hit = [i for i in issues if i["title"] == "postMessage listener (runtime)"]
    assert hit and "3 postMessage handlers" in hit[0]["detail"]


def test_without_hook_degrades_gracefully():
    # no hook: still runs and returns something (it can't defend against tampering without the saved built-ins,
    # so here the page's fake JSON.stringify wins — which is exactly what the hook prevents above)
    snap, _ = _snapshot([])
    assert snap
