#------------------------------------------------------------------------------
# Wyrm — tests/test_capture.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""F1 + B1: a page must not be able to forge Traffic/API capture rows, genuine fetch/XHR/WebSocket rows must
still arrive, and capture must handle URL/Request inputs, request bodies and headers, rejected fetches and
binary/JSON XHR responses. Browser tests load the shipped capture.js into a real QtWebEngine tab on 127.0.0.1.
Run: `python -m pytest tests/test_capture.py`."""
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wyrm.browser import capturemsg  # noqa: E402

SITE = Path(__file__).resolve().parent / "capture"


# ---- Python-side validation ------------------------------------------------------------------------------
def _p(**kw):
    return capturemsg.parse(json.dumps(kw), "http://127.0.0.1:8777/")


def test_valid_rows_pass_and_page_comes_from_qt():
    r = _p(k="fetch", url="http://127.0.0.1/a", method="GET", status=200, req="", res="ok", page="https://evil/")
    assert r["page"] == "http://127.0.0.1:8777/" and r["source"] == "page-reported" and r["status"] == 200
    assert _p(k="ws", url="ws://127.0.0.1/s", ev="recv", res="hi")["ev"] == "recv"


@pytest.mark.parametrize("bad", [
    dict(k="navigate", url="x"),                                    # unknown kind
    dict(k="ws", url="x", ev="hijack"),                             # unknown ws event
    dict(k="fetch", url="x", method="GET", status=1000),            # status out of range
    dict(k="fetch", url="x", method="GET", status="200"),           # status not int
    dict(k="fetch", url="x", method="GET", status=True),            # bool is not a status
    dict(k="fetch", url="x", method="get <b>", status=200),         # bad method
    dict(k="fetch", url="x" * 5000, method="GET", status=200),      # oversized url
    dict(k="fetch", url="x", method="GET", status=200, res="y" * 20000),
    dict(k="fetch", url=["x"], method="GET", status=200),
    dict(k="xhr", url="x", method="GET", status=200, headers={"a": 1}),
])
def test_invalid_rows_are_rejected(bad):
    assert _p(**bad) is None


def test_unknown_keys_are_dropped():
    r = _p(k="xhr", url="u", method="GET", status=200, html="<script>", evil=1)
    assert "html" not in r and "evil" not in r


def test_garbage_is_rejected():
    assert capturemsg.parse("not json") is None
    assert capturemsg.parse("[1,2]") is None
    assert capturemsg.parse("{" + " " * 300000 + "}") is None


# ---- real browser ---------------------------------------------------------------------------------------
def _browser_rows(page):
    pytest.importorskip("PySide6.QtWebEngineCore")
    from webharness import run_page
    from wyrm.browser.scripts import CAP_PREFIX, CAPTURE_JS
    msgs = run_page(SITE, page, [("wyrm-capture", CAPTURE_JS)])
    assert "WYRM_TEST_DONE" in msgs, f"page never finished: {msgs}"
    rows = [capturemsg.parse(m[len(CAP_PREFIX):], "http://127.0.0.1/") for m in msgs if m.startswith(CAP_PREFIX)]
    assert None not in rows, "capture.js emitted a row the validator rejects"
    return rows


def test_page_cannot_forge_rows():
    rows = _browser_rows("forge.html")
    blob = json.dumps(rows)
    assert "FORGED" not in blob and "injected by page" not in blob and "bank.example" not in blob
    real = [r for r in rows if r["url"].endswith("/api/v1/users")]
    assert len(real) == 1 and real[0]["status"] == 200 and '"admin"' in real[0]["res"]
    assert real[0]["t"] != 42                                   # Date.now was replaced by the page


def test_genuine_rows_and_b1_cases():
    rows = _browser_rows("genuine.html")
    by = {}
    for r in rows:
        by.setdefault(r["url"].split("/")[-1], []).append(r)
    plain = by["users"][0]
    assert plain["k"] == "fetch" and plain["status"] == 200 and plain["headers"].get("X-Test") == "1"
    assert by["users?via=url"][0]["url"].startswith("http://127.0.0.1:")      # URL object no longer ""
    req = by["users?via=req"][0]
    assert req["method"] == "POST" and req["req"] == "reqbody=1"               # Request body read via clone
    bad = by["unreachable"][0]
    assert bad["status"] == 0 and bad.get("error")                            # rejected fetch is logged
    xj = by["users?via=xhr"][0]
    assert xj["k"] == "xhr" and '"admin"' in xj["res"] and xj["headers"].get("X-Xhr") == "yes"
    assert by["users?via=bin"][0]["res"].startswith("[binary ")               # size, not "[arraybuffer]"
    ws = by["sock"]
    assert ws[0]["k"] == "ws" and ws[0]["ev"] == "open"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
