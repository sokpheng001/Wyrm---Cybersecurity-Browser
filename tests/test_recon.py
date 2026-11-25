#------------------------------------------------------------------------------
# Wyrm — tests/test_recon.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""QA-H2: the well-known (robots/sitemap/security.txt) lookup must keep the target's real scheme and port
instead of forcing https:// on the default port."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wyrm.panels.recon import _origin_from  # noqa: E402


def test_origin_keeps_scheme_and_port_from_url():
    assert _origin_from("http://127.0.0.1:8765/x")[0] == "http://127.0.0.1:8765"


def test_origin_from_host_port_defaults_to_http():
    assert _origin_from("127.0.0.1:8765")[0] == "http://127.0.0.1:8765"


def test_origin_bare_host_defaults_to_https():
    assert _origin_from("example.com")[0] == "https://example.com"


def test_origin_stored_use_current_wins_for_same_host():
    # 'Use current' on http://127.0.0.1:8765 stores the origin; the box then shows just the host
    assert _origin_from("127.0.0.1", "http://127.0.0.1:8765")[0] == "http://127.0.0.1:8765"


def test_origin_empty_is_none():
    assert _origin_from("")[0] is None


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
