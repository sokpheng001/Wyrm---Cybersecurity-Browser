#------------------------------------------------------------------------------
# Wyrm — tests/test_severity.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""QA-M1: the same weakness must carry the same severity whichever tool reports it, and display in one form."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wyrm.security import analyzer, severity  # noqa: E402
from wyrm.security.audit import passive         # noqa: E402

_RESP = {"headers": {"content-type": "text/html"}, "status": 200, "text": "<html></html>"}


def _sev_of(issues, needle):
    return next((i["severity"] for i in issues if needle in i.get("title", "").lower()), None)


def test_csp_severity_equal_across_tools():
    a = _sev_of(analyzer.evaluate_csp(None, None), "no content-security-policy")
    p = _sev_of(passive.check_response("https://t/", _RESP), "content-security-policy")
    assert a == p == severity.DEFAULTS["missing-csp"]


def test_clickjacking_severity_equal_across_tools():
    a = _sev_of(analyzer.check_headers({"headers": {}}, True), "clickjacking")
    p = _sev_of(passive.check_response("https://t/", _RESP), "clickjacking")
    assert a == p == severity.DEFAULTS["missing-clickjacking"]


def test_title_is_consistent_title_case():
    assert severity.title("medium") == "Medium"
    assert severity.title("MEDIUM") == "Medium"
    assert severity.title("warning") == "warning"   # not a level -> unchanged (and no tool emits it now)


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
