#------------------------------------------------------------------------------
# Wyrm — tests/test_home_weather.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""W1: the start-page weather must read "4°C Clear", not "4°CClear" — in the markup and on screen."""
import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wyrm import pages  # noqa: E402

CTX = {"weather": {"temp_c": 4.2, "desc": "Clear", "emoji": "☀️", "city": "Busan", "country": "KR"},
       "weather_on": True, "location_on": True}

PROBE = """<script>addEventListener('load',function(){
var t=document.querySelector('.wx .temp'),d=document.querySelector('.wx .desc');
var r={text:document.querySelector('.wx .wxcond').textContent,
       gap:d.getBoundingClientRect().left-t.getBoundingClientRect().right};
console.log('WXRESULT '+JSON.stringify(r));console.log('WYRM_TEST_DONE');});</script>"""


def _html():
    return pages.render_home(dict(CTX))


def test_markup_has_a_space():
    html = _html()
    assert "4°C</span> <span class='desc'>Clear" in html


def test_rendered_gap():
    pytest.importorskip("PySide6.QtWebEngineCore")
    from webharness import run_page
    with tempfile.TemporaryDirectory() as d:
        Path(d, "home.html").write_text(_html().replace("</body>", PROBE + "</body>"), encoding="utf-8")
        msgs = run_page(d, "home.html")
    res = json.loads(next(m for m in msgs if m.startswith("WXRESULT "))[9:])
    assert "4°C Clear" in res["text"].replace(" ", " ")
    assert res["gap"] >= 4, res
