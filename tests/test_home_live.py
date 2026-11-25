#------------------------------------------------------------------------------
# Wyrm — tests/test_home_live.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""W2: feed/weather updates patch the open start page in place (no reload, no flash, scroll and typed text kept),
and the patch script refuses to touch any page that isn't Wyrm's own start page."""
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wyrm import pages  # noqa: E402

pytest.importorskip("PySide6.QtWebEngineCore")
from wyrm.mainwindow.home import HomeMixin  # noqa: E402

OLD = {"weather_on": True, "location_on": True, "shortcuts": [], "news": [], "kev": []}
NEW = dict(OLD, weather={"temp_c": 4, "desc": "Clear", "emoji": "☀️", "city": "Busan"},
           kev=[{"id": "CVE-2099-0001", "vendor": "Acme", "product": "Widget", "name": "RCE", "added": "2026-11-25"}])
GUARD = HomeMixin._LIVE_PATCH_JS.split("var cur=")[0]


def _run(patch_js):
    from webharness import run_page
    patch_js = patch_js.replace("</", "<\\/")   # inline <script> only; the app passes it via runJavaScript
    probe = ("<script>addEventListener('load',function(){var q=document.querySelector('input[name=q]');"
             "q.value='typed';window.__marker=1;var r=" + patch_js + ";"
             "console.log('LIVE '+JSON.stringify({r:r,marker:window.__marker===1,typed:q.value,"
             "wx:(document.querySelector('[data-live=wx]')||{}).textContent||'',"
             "kev:!!document.querySelector('.cve')}));console.log('WYRM_TEST_DONE');});</script>")
    with tempfile.TemporaryDirectory() as d:
        Path(d, "home.html").write_text(pages.render_home(dict(OLD)).replace("</body>", probe + "</body>"),
                                        encoding="utf-8")
        msgs = run_page(d, "home.html")
    return json.loads(next(m for m in msgs if m.startswith("LIVE "))[5:])


def test_live_regions_exist():
    html = pages.render_home(dict(OLD))
    for k in ("wx", "sc", "feeds"):
        assert f"data-live='{k}'" in html


def test_patch_updates_in_place():
    js = (HomeMixin._LIVE_PATCH_JS % json.dumps(pages.render_home(dict(NEW)))).replace(GUARD, "(function(h){")
    res = _run(js)
    assert res["r"] >= 2 and res["kev"] and "4°C Clear" in res["wx"]
    assert res["marker"] and res["typed"] == "typed"      # same document: nothing reloaded, input kept


def test_patch_refuses_foreign_pages():
    res = _run(HomeMixin._LIVE_PATCH_JS % json.dumps(pages.render_home(dict(NEW))))
    assert res["r"] == -2 and not res["kev"]              # served over http, not wyrm://home
