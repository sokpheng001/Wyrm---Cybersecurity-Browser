#------------------------------------------------------------------------------
# Wyrm — tests/test_version.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""QA-H1: version_label() must surface the build SHA so a tester can pin the exact build, and must never crash
when the generated _buildinfo is absent (source checkout)."""
import os
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import wyrm  # noqa: E402


def test_version_label_contains_sha_when_buildinfo_present():
    fake = types.ModuleType("wyrm._buildinfo")
    fake.SHA = "deadbee"
    fake.BUILD_TIME = "2026-11-25 11:17"
    sys.modules["wyrm._buildinfo"] = fake
    try:
        label = wyrm.version_label()
    finally:
        del sys.modules["wyrm._buildinfo"]
    assert wyrm.__version__ in label
    assert "deadbee" in label
    assert "2026-11-25 11:17" in label


def test_version_label_does_not_crash_without_buildinfo():
    sys.modules.pop("wyrm._buildinfo", None)
    label = wyrm.version_label()
    assert isinstance(label, str) and wyrm.__version__ in label
    # from a source checkout it's a dev build (no CI build stamp)
    assert "dev" in label or "build" in label


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
