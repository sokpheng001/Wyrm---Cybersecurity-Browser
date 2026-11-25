#------------------------------------------------------------------------------
# Wyrm — tests/test_fingerprint.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""F2: anti-fingerprinting must not make users easier to identify. Loads the shipped fingerprint.js (as Wyrm
injects it) into a real QtWebEngine tab running tests/fp/fp.html on 127.0.0.1 and requires every check to pass.
Run: `python -m pytest tests/test_fingerprint.py`."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from wyrm.browser import scripts  # noqa: E402


@pytest.mark.parametrize("plat,needle,forbidden", [
    ("darwin", "Apple", "D3D"), ("win32", "D3D11", "Metal"), ("linux", "OpenGL", "D3D")])
def test_renderer_matches_platform(plat, needle, forbidden):
    for seed in range(1, 20):
        cfg = scripts.fingerprint_config(plat, seed)
        assert needle in cfg["renderer"] and forbidden not in cfg["renderer"]
        assert cfg["seed"] == seed


def test_session_seed_is_baked_in_once():
    a, b = scripts.fingerprint_js(), scripts.fingerprint_js()
    assert a == b and str(scripts.FP_SEED) in a and "__WYRM_FP_CONFIG__" not in a


def test_fp_page_in_browser():
    pytest.importorskip("PySide6.QtWebEngineCore")
    from webharness import run_page
    msgs = run_page(Path(__file__).resolve().parent / "fp", "fp.html", [("wyrm-antifp", scripts.FINGERPRINT_JS)])
    line = next((m for m in msgs if m.startswith("FPRESULT ")), None)
    assert line, f"fp.html produced no result: {msgs}"
    res = json.loads(line[len("FPRESULT "):])
    failed = {k: v["detail"] for k, v in res.items() if not v["ok"]}
    assert not failed, failed
    assert "(no webgl)" not in res["WebGL renderer matches UA platform"]["detail"], "WebGL unavailable"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
