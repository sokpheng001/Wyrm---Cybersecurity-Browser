#------------------------------------------------------------------------------
# Wyrm — tests/test_scope_passive.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""B8: active ProjectDiscovery tools launch only for targets inside the engagement scope (checked at the single
launch point, pdtools.run), and auto security mode stays passive: no tool processes, GET requests only.
Everything runs against 127.0.0.1."""
import http.server
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wyrm.security import analyzer, pdtools  # noqa: E402

NUCLEI, NAABU, SUBFINDER = (pdtools.TOOLS_BY_KEY[k] for k in ("nuclei", "naabu", "subfinder"))


@pytest.mark.parametrize("tool,target,scope", [
    (NUCLEI, "http://127.0.0.1:8777/", []),                        # no engagement scope
    (NUCLEI, "http://evil.example/", ["127.0.0.1"]),               # out of scope
    (NUCLEI, "?//other.test/x", ["*.example.com"]),
    (NAABU, "10.0.0.0/16", ["10.0.0.0"]),                          # range bigger than the one in-scope host
    (NAABU, "10.0.0.0/24", ["10.0.0.0/24", "!10.0.0.7"]),          # an excluded address inside the range
    (NAABU, "10.0.0.0/8", ["10.0.0.0/8"]),                         # too large to verify
])
def test_active_tools_refuse_out_of_scope(tool, target, scope, monkeypatch):
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("a tool process was started"))
    with pytest.raises(pdtools.OutOfScope):
        pdtools.run(tool, target, lambda *a: None, scope=scope)


@pytest.mark.parametrize("tool,target,scope", [
    (NUCLEI, "http://127.0.0.1:8777/", ["127.0.0.1"]),
    (NUCLEI, "https://api.example.com/v1", ["*.example.com"]),
    (NAABU, "10.0.0.0/30", ["10.0.0.0/24"]),
    (SUBFINDER, "example.com", []),                                # passive tool: no scope needed
])
def test_in_scope_or_passive_is_allowed(tool, target, scope):
    pdtools.check_scope(tool, target, scope)


class _H(http.server.BaseHTTPRequestHandler):
    methods = []

    def _ok(self):
        _H.methods.append(self.command)
        body = b"<html><script src='/app.js'></script>ok</html>" if self.path == "/" else b"var a=1;"
        self.send_response(200)
        self.send_header("Content-Type", "text/html" if self.path == "/" else "application/javascript")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_PUT = do_DELETE = do_OPTIONS = _ok

    def log_message(self, *a):
        pass


def test_auto_analysis_is_passive(monkeypatch):
    _H.methods = []
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}/"
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: pytest.fail("auto mode started a tool process"))
    monkeypatch.setattr(pdtools, "run", lambda *a, **k: pytest.fail("auto mode launched a pdtools scan"))
    try:
        page = {"url": url, "https": False, "scripts": [url + "app.js"], "inline": [], "forms": []}
        res = analyzer.analyze(url, page, in_scope=lambda h: h == "127.0.0.1")   # what page_loaded() runs
    finally:
        srv.shutdown()
    assert "issues" in res
    assert _H.methods and set(_H.methods) == {"GET"}, _H.methods       # the page + its own script, GET only
    assert len(_H.methods) <= 3


def test_cidr_scope_entries_cover_their_range():
    from wyrm.security.store import host_in_scope
    assert host_in_scope("10.0.0.200", ["10.0.0.0/24"])            # was reduced to 10.0.0.0 only
    assert not host_in_scope("10.0.1.1", ["10.0.0.0/24"])
    assert host_in_scope("app.example.com", ["https://app.example.com/login"])   # URL paths still dropped
