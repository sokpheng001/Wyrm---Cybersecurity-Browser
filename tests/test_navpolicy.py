#------------------------------------------------------------------------------
# Wyrm — tests/test_navpolicy.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""SEC-10 regression tests: a web page must not be able to navigate the browser to a privileged (wyrm://),
local (file://) or script (javascript:) scheme, nor to a top-level data: URL. The user (address bar / history)
and Wyrm's own wyrm:// chrome still may. Run: `python -m pytest tests/test_navpolicy.py` (or run this file)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wyrm import navpolicy  # noqa: E402


def _page_click(target, is_main_frame=True, current="https"):
    """A web page (current scheme https) initiating a link click / redirect / script navigation."""
    return navpolicy.should_block(target, is_main_frame=is_main_frame, user_driven=False, current_scheme=current)


def test_page_cannot_reach_privileged_or_local_schemes():
    assert _page_click("wyrm") is True          # wyrm://history et al.
    assert _page_click("file") is True          # local filesystem
    assert _page_click("javascript") is True     # in-URL script
    assert _page_click("data", is_main_frame=True) is True   # top-level data: navigation


def test_page_can_still_use_normal_schemes():
    assert _page_click("https") is False
    assert _page_click("http") is False
    assert _page_click("mailto") is False
    assert _page_click("data", is_main_frame=False) is False  # data: image / sub-frame is fine


def test_user_driven_navigation_is_allowed():
    # address bar (typed) / history (back-forward) / reload reach even guarded schemes
    for scheme in ("wyrm", "file", "data"):
        assert navpolicy.should_block(scheme, is_main_frame=True, user_driven=True, current_scheme="https") is False


def test_wyrm_chrome_may_navigate_itself():
    # our own wyrm:// pages (and the initial blank load) may navigate between wyrm:// addresses
    assert navpolicy.should_block("wyrm", is_main_frame=True, user_driven=False, current_scheme="wyrm") is False
    assert navpolicy.should_block("wyrm", is_main_frame=True, user_driven=False, current_scheme="") is False


def test_local_page_can_browse_the_local_filesystem():
    # a page already loaded from file:// may click into folders / local files (directory browsing)
    assert navpolicy.should_block("file", is_main_frame=True, user_driven=False, current_scheme="file") is False
    assert navpolicy.should_block("file", is_main_frame=False, user_driven=False, current_scheme="file") is False
    # but a local page still can't jump to privileged / script schemes on its own
    assert navpolicy.should_block("wyrm", is_main_frame=True, user_driven=False, current_scheme="file") is True
    assert navpolicy.should_block("javascript", is_main_frame=True, user_driven=False, current_scheme="file") is True


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
