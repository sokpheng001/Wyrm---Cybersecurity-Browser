#------------------------------------------------------------------------------
# Wyrm — tests/test_addons.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Add-on API tests: an add-on can register a custom scanner check that runs in the audit engine alongside the
built-ins. Run: `python -m pytest tests/test_addons.py` (or run this file directly)."""
import os
import sys
import tempfile
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wyrm.addons.api import AddonContext      # noqa: E402
from wyrm.security.audit import engine         # noqa: E402


def _ctx():
    win = types.SimpleNamespace(data_dir=tempfile.mkdtemp())
    return AddonContext(win, {"name": "demo", "_id": "demo"}), win


class _MyCheck:
    key = "addon-demo"
    title = "Add-on demo finding"
    severity = "info"

    def run_request(self, method, url, headers, body, send, baseline, rand, oob=None):
        return {"check": self.key, "title": self.title, "severity": self.severity, "confidence": "firm",
                "loc": "request", "param": "", "payload": "", "evidence": "registered by an add-on",
                "status": 200, "url": url}


def test_add_scan_check_is_stored_on_the_window():
    ctx, win = _ctx()
    ctx.add_scan_check(_MyCheck())
    assert getattr(win, "_addon_scan_checks", None) and len(win._addon_scan_checks) == 1


def test_addon_check_runs_in_the_engine():
    ctx, win = _ctx()
    ctx.add_scan_check(_MyCheck())

    def send(method, url, headers, body):
        return {"status": 200, "headers": {}, "text": "", "location": "", "url": url}

    findings = engine.scan({"method": "GET", "url": "http://t.test/", "headers": {}, "body": ""},
                           send, checks=win._addon_scan_checks, passive=False)
    assert any(f["title"] == "Add-on demo finding" for f in findings)


def test_flows_snapshot_is_read_only_copy():
    from wyrm.security import mitm
    ctx, win = _ctx()
    assert ctx.flows() == []                      # proxy off -> empty
    fake = types.SimpleNamespace(flows=[{"url": "https://a/"}, {"url": "https://b/"}])
    mitm.ACTIVE = fake
    try:
        snap = ctx.flows()
        assert len(snap) == 2 and snap[0]["url"] == "https://a/"
        snap.append({"url": "x"})                  # mutating the copy must not affect the proxy
        assert len(fake.flows) == 2
    finally:
        mitm.ACTIVE = None


def test_per_point_addon_check_also_runs():
    ctx, win = _ctx()

    class PointCheck:
        key, title, severity = "addon-point", "Point add-on finding", "low"

        def run(self, point, build, send, baseline, rand, oob=None):
            if point["loc"] == "query":
                return {"check": self.key, "title": self.title, "severity": self.severity, "confidence": "firm",
                        "loc": point["loc"], "param": point["name"], "payload": "x", "evidence": "y",
                        "status": 200, "url": "http://t.test/"}
            return None
    ctx.add_scan_check(PointCheck())

    def send(method, url, headers, body):
        return {"status": 200, "headers": {}, "text": "", "location": "", "url": url}

    findings = engine.scan({"method": "GET", "url": "http://t.test/?q=1", "headers": {}, "body": ""},
                           send, checks=win._addon_scan_checks, passive=False)
    assert any(f["title"] == "Point add-on finding" for f in findings)


def _load_example(rel):
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "examples", "addons", rel)
    spec = importlib.util.spec_from_file_location("wyrm_example_addon", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_example_permissions_policy_addon():
    mod = _load_example(os.path.join("permissions-policy-check", "main.py"))
    ctx, win = _ctx()
    mod.register(ctx)
    assert len(win._addon_scan_checks) == 1

    def send_missing(method, url, headers, body):
        return {"status": 200, "headers": {"content-type": "text/html"}, "text": "<h1>hi</h1>",
                "location": "", "url": url}

    def send_present(method, url, headers, body):
        return {"status": 200, "headers": {"content-type": "text/html", "permissions-policy": "geolocation=()"},
                "text": "<h1>hi</h1>", "location": "", "url": url}

    req = {"method": "GET", "url": "http://t.test/", "headers": {}, "body": ""}
    flagged = engine.scan(req, send_missing, checks=win._addon_scan_checks, passive=False)
    assert any(f["check"] == "addon-permissions-policy" for f in flagged)
    clean = engine.scan(req, send_present, checks=win._addon_scan_checks, passive=False)
    assert not any(f["check"] == "addon-permissions-policy" for f in clean)


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
