#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/capture.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Developer: Kwan (in-page API & WebSocket capture)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""In-page capture of fetch/XHR request+response bodies and WebSocket frames (opt-in, read-only).

A script (capture.js) injected into pages hooks fetch/XHR/WebSocket and reports each one through a sentinel
console message, which _CapturePage forwards to _on_capture() here. This shows the API traffic and WebSocket
frames that a pentester cares about — with bodies — without a MITM proxy. It does not capture top-level
navigations or static sub-resources (images, CSS); that needs the proxy. Off by default.
"""
from __future__ import annotations

import json


class CaptureMixin:
    """API & WebSocket capture. (Mixed into MainWindow.)"""

    def _init_capture(self):
        if not hasattr(self, "captures"):
            self.captures: list = []

    def capture_enabled(self) -> bool:
        return self.settings.value("capture/enabled", False, type=bool)

    def set_capture_enabled(self, on: bool):
        self._init_capture()
        self.settings.setValue("capture/enabled", bool(on))
        from PySide6.QtWebEngineCore import QWebEngineScript
        from ..browser.scripts import CAPTURE_JS
        for prof in self.profiles.values():
            scripts = prof.scripts()
            existing = scripts.find("wyrm-capture")
            for sc in existing:
                scripts.remove(sc)
            if on:
                sc = QWebEngineScript()
                sc.setName("wyrm-capture")
                sc.setSourceCode(CAPTURE_JS)
                sc.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
                sc.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
                sc.setRunsOnSubFrames(True)
                scripts.insert(sc)
        self.toast("Capturing API & WebSocket traffic — reload pages to start" if on
                   else "Capture off", 5000)

    def _on_capture(self, payload: str):
        """Called (UI thread) from _CapturePage for each sentinel console message."""
        # Defence in depth (SEC-4): even though the sentinel carries an unguessable per-process token, ignore
        # anything that arrives while capture is off, so a page can never add rows unless the user opted in.
        if not self.capture_enabled():
            return
        self._init_capture()
        try:
            rec = json.loads(payload)
        except ValueError:
            return
        self.captures.append(rec)
        del self.captures[:-500]  # keep the most recent 500
        tab = getattr(self.security, "capture", None)
        if tab is not None:
            tab.add_record(rec)
