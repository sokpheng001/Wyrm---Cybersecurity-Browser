#------------------------------------------------------------------------------
# Wyrm — tests/test_scanner.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""QA-H3: JS recon must use the Target field and be scope-gated — no network fetch for an out-of-scope host.

The network-fetch decision is the pure _js_plan(): only 'fetch' downloads the target page, and only 'dom' with
external fetching touches the network. For an out-of-scope host neither is ever chosen, so no request is sent."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wyrm.panels.scanner import _js_plan, _same_origin  # noqa: E402


def test_out_of_scope_host_never_fetches():
    # different-origin out-of-scope target -> refuse (nothing is sent)
    assert _js_plan("http://127.0.0.1:8765/api/data", "wyrm://home", False) == "refuse"
    assert _js_plan("http://127.0.0.1:8765/api/data", "", False) == "refuse"
    # even a same-origin out-of-scope tab only reads inline scripts (no external network fetch)
    assert _js_plan("http://127.0.0.1:8765/", "http://127.0.0.1:8765/page", False) == "dom_inline"


def test_in_scope_uses_dom_or_fetch():
    assert _js_plan("http://127.0.0.1:8765/x", "http://127.0.0.1:8765/", True) == "dom"
    assert _js_plan("http://127.0.0.1:8765/x", "http://other.test/", True) == "fetch"
    assert _js_plan("http://127.0.0.1:8765/x", "", True) == "fetch"


def test_same_origin_is_scheme_host_port():
    assert _same_origin("http://t:8765/a", "http://t:8765/b")
    assert not _same_origin("http://t:8765/", "http://t:9000/")   # different port
    assert not _same_origin("http://t/", "https://t/")            # different scheme


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)


def test_pd_summary_says_input_and_whether_target_is_contacted():
    from wyrm.panels.scanner import pd_summary
    from wyrm.security import pdtools
    active = next(t for t in pdtools.TOOLS if t.active)
    passive = next(t for t in pdtools.TOOLS if not t.active)
    assert "Contacts the target" in pd_summary(active)
    assert "Passive" in pd_summary(passive) and "Contacts" not in pd_summary(passive)
    assert "Enter " in pd_summary(active)
