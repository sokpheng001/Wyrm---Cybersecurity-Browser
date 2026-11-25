#------------------------------------------------------------------------------
# Wyrm — tests/test_audit_checks.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Tests for the active-scanner checks (wyrm/security/audit/checks.py).

Focus: the new blind/time-based SQL injection check. A fake `send` sleeps for the number of seconds embedded in
a SLEEP()/pg_sleep()/WAITFOR payload, so the check's timing oracle is exercised with small, fast durations.
Run: `python -m pytest tests/test_audit_checks.py` (or run this file directly)."""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wyrm.security.audit import checks as chk  # noqa: E402

_SLEEP = re.compile(r"(?:SLEEP|pg_sleep)\((\d+(?:\.\d+)?)\)|WAITFOR DELAY '0:0:(\d+(?:\.\d+)?)'", re.I)


def _point():
    return {"loc": "query", "name": "id", "value": "1"}


def _build(payload):
    # the real builders url-encode; for a unit test we keep the payload readable so the fake DB can see the sleep
    return ("http://target/items?id=" + payload, {}, None)


def _make_send(sleeps=True, fixed_delay=0.0):
    def send(url, headers, body):
        if fixed_delay:
            time.sleep(fixed_delay)                 # a naturally slow endpoint (no injection)
        elif sleeps:
            m = _SLEEP.search(url)
            if m:
                time.sleep(float(m.group(1) or m.group(2)))   # DB executed our sleep
        return {"status": 200, "headers": {}, "text": "ok", "location": "", "url": url}
    return send


FAST = (0.4, 0.8)   # keep the test quick while preserving the 1x/2x relationship


def test_blind_sqli_detected_when_time_scales():
    c = chk.SqlBlindTime(time_based=True, probe_secs=FAST)
    f = c.run(_point(), _build, _make_send(sleeps=True), baseline=None, rand="abc")
    assert f is not None, "a sleepable parameter should be flagged"
    assert f["check"] == "sqli" and f["severity"] == "high"
    assert f["confidence"] == "firm"


def test_no_finding_when_endpoint_ignores_sleep():
    c = chk.SqlBlindTime(time_based=True, probe_secs=FAST)
    f = c.run(_point(), _build, _make_send(sleeps=False), baseline=None, rand="abc")
    assert f is None


def test_no_false_positive_on_naturally_slow_endpoint():
    # every response is slow (>= n1*0.9) but not injectable — the baseline guard must suppress the finding
    c = chk.SqlBlindTime(time_based=True, probe_secs=FAST)
    f = c.run(_point(), _build, _make_send(sleeps=False, fixed_delay=0.5), baseline=None, rand="abc")
    assert f is None


def test_time_based_off_skips_the_check():
    c = chk.SqlBlindTime(time_based=False, probe_secs=FAST)
    f = c.run(_point(), _build, _make_send(sleeps=True), baseline=None, rand="abc")
    assert f is None


def test_blind_sqli_is_in_the_standard_thorough_set_only():
    names = [type(c).__name__ for c in chk.standard(time_based=True)]
    assert "SqlBlindTime" in names
    fast = chk.standard(time_based=False)
    # present in Fast too, but inert (its run() returns None when time_based is off)
    sb = [c for c in fast if type(c).__name__ == "SqlBlindTime"]
    assert sb and sb[0].time_based is False


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
