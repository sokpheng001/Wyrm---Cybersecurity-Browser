#------------------------------------------------------------------------------
# Wyrm — tests/webharness.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Tiny test harness: load a local page in a real QtWebEngine (Chromium) tab with Wyrm's injected scripts and
collect its console messages. Everything is served from 127.0.0.1 — no third-party hosts are ever contacted.

    msgs = run_page(site_dir, "index.html", scripts=[("wyrm-capture", CAPTURE_JS)])

The page signals completion with console.log("WYRM_TEST_DONE"); otherwise we stop at `timeout`.
"""
from __future__ import annotations

import functools
import http.server
import os
import threading

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QTWEBENGINE_CHROMIUM_FLAGS", "--disable-gpu --no-sandbox")

DONE = "WYRM_TEST_DONE"
_app = None


def _qapp():
    global _app
    from PySide6.QtCore import QCoreApplication, Qt
    from PySide6.QtWidgets import QApplication
    if _app is None:
        _app = QApplication.instance()
        if _app is None:
            QCoreApplication.setAttribute(Qt.ApplicationAttribute.AA_ShareOpenGLContexts)
            _app = QApplication(["wyrm-tests"])
    return _app


class _Quiet(http.server.SimpleHTTPRequestHandler):
    extra = {}  # path -> (content-type, bytes); lets a test serve generated responses

    def do_GET(self):  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in self.extra:
            ctype, body = self.extra[path]
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        return super().do_GET()

    do_POST = do_GET  # noqa: N815

    def log_message(self, *a):
        pass


def serve(directory, extra=None):
    """Start a local HTTP server for `directory` on 127.0.0.1 (random port). Returns (server, base_url)."""
    handler = type("H", (_Quiet,), {"extra": dict(extra or {})})
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), functools.partial(handler, directory=str(directory)))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def run_page(directory, page="index.html", scripts=(), timeout=10.0, extra=None):
    """Load `page` from `directory` with `scripts` ((name, source) pairs) injected at document creation in the
    main world of every frame — exactly how Wyrm injects them. Returns the list of console messages."""
    _qapp()
    from PySide6.QtCore import QEventLoop, QTimer, QUrl
    from PySide6.QtWebEngineCore import QWebEnginePage, QWebEngineProfile, QWebEngineScript

    msgs: list[str] = []
    loop = QEventLoop()

    class Page(QWebEnginePage):
        def javaScriptConsoleMessage(self, level, message, line, source):  # noqa: N802
            msgs.append(message)
            if message == DONE:
                QTimer.singleShot(300, loop.quit)  # let trailing async emits land

    prof = QWebEngineProfile()  # off-the-record
    for name, src in scripts:
        sc = QWebEngineScript()
        sc.setName(name)
        sc.setSourceCode(src)
        sc.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        sc.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        sc.setRunsOnSubFrames(True)
        prof.scripts().insert(sc)
    pg = Page(prof)
    srv, base = serve(directory, extra)
    try:
        QTimer.singleShot(int(timeout * 1000), loop.quit)
        pg.load(QUrl(base + page))
        loop.exec()
    finally:
        srv.shutdown()
        from PySide6.QtCore import QCoreApplication, QEvent
        pg.deleteLater()  # page first, then its profile (Qt warns otherwise)
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        prof.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    return msgs
