#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/intercept.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Intercept (Burp-style): hold page requests, edit them, then forward, drop or send to Repeater.

While Intercept is on, every top-level page request the browser makes (link clicks, typed URLs, form GETs and
POSTs) is held instead of sent. Each held request can be edited (method, URL, headers, body) and forwarded: the
browser then loads exactly the edited request (QWebEngineHttpRequest), so the response renders in the tab as
usual. Sub-resources (images, scripts, XHR) are not held; use Match & Replace for their headers.
"""
from __future__ import annotations

from html import escape

from PySide6.QtCore import QByteArray, QUrl, Qt
from PySide6.QtWidgets import (QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
                               QPlainTextEdit, QPushButton, QSplitter, QVBoxLayout, QWidget)

from .common import HeaderHighlighter, mono

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
# Headers Chromium sets itself; sending them again from an edited request breaks the load
_SKIP = {"host", "content-length", "connection", "accept-encoding", "cookie"}


class InterceptWindow(QWidget):
    """The Intercept window: queue of held requests on the left, editor on the right."""

    def __init__(self, win):
        super().__init__(None, Qt.WindowType.Window)
        self.win = win
        self.setWindowTitle("Intercept — Wyrm Browser")
        self.resize(980, 620)
        self._held: list[dict] = []
        v = QVBoxLayout(self)
        v.setContentsMargins(14, 12, 14, 12)
        top = QHBoxLayout()
        self.toggle = QCheckBox("Intercept is ON")
        self.toggle.setChecked(True)
        self.toggle.toggled.connect(self._toggled)
        top.addWidget(self.toggle)
        self.count = QLabel("")
        self.count.setObjectName("Muted")
        top.addWidget(self.count, 1)
        self.b_forward = QPushButton("Forward")
        self.b_forward.setObjectName("Primary")
        self.b_forward.setToolTip("Send this (edited) request; the page loads in its tab (Ctrl+F)")
        self.b_forward.setShortcut("Ctrl+F")
        self.b_forward.clicked.connect(self.forward)
        self.b_drop = QPushButton("Drop")
        self.b_drop.setToolTip("Discard this request: it is never sent (Ctrl+D)")
        self.b_drop.setShortcut("Ctrl+D")
        self.b_drop.clicked.connect(self.drop)
        self.b_rep = QPushButton("Send to Repeater")
        self.b_rep.setToolTip("Copy this request into a Repeater tab (it stays held here)")
        self.b_rep.clicked.connect(self.to_repeater)
        self.b_intr = QPushButton("Send to Intruder")
        self.b_intr.setToolTip("Copy this request into Intruder to fuzz it (it stays held here)")
        self.b_intr.clicked.connect(self.to_intruder)
        self.b_all = QPushButton("Forward all")
        self.b_all.clicked.connect(self.forward_all)
        for b in (self.b_forward, self.b_drop, self.b_rep, self.b_intr, self.b_all):
            top.addWidget(b)
        v.addLayout(top)

        split = QSplitter(Qt.Orientation.Horizontal)
        self.queue = QListWidget()
        self.queue.currentRowChanged.connect(self._show)
        split.addWidget(self.queue)
        ed = QWidget()
        e = QVBoxLayout(ed)
        e.setContentsMargins(8, 0, 0, 0)
        line = QHBoxLayout()
        self.method = QComboBox()
        self.method.setEditable(True)
        self.method.addItems(METHODS)
        self.method.setFixedWidth(110)
        line.addWidget(self.method)
        self.url = mono(QLineEdit())
        line.addWidget(self.url, 1)
        e.addLayout(line)
        e.addWidget(QLabel("Headers (one per line)"))
        self.headers = mono(QPlainTextEdit())
        self._hl = HeaderHighlighter(self.headers)
        e.addWidget(self.headers, 2)
        e.addWidget(QLabel("Body"))
        self.body = mono(QPlainTextEdit())
        e.addWidget(self.body, 1)
        split.addWidget(ed)
        split.setSizes([300, 680])
        v.addWidget(split, 1)
        hint = QLabel("Holds page requests (links, typed URLs, form submissions) while ON. Images, scripts and XHR "
                      "pass through; use Tools → Match & Replace for their headers. Only test systems you're "
                      "authorized to test.")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        v.addWidget(hint)
        self._refresh()

    # ---------------------------------------------------------------- queue
    def hold(self, view, req: dict):
        req["view"] = view
        self._held.append(req)
        it = QListWidgetItem(f"{req['method']}  {req['url']}")
        it.setToolTip(req["url"])
        self.queue.addItem(it)
        if self.queue.currentRow() < 0:
            self.queue.setCurrentRow(0)
        self._refresh()
        self.show()
        self.raise_()

    def _refresh(self):
        n = len(self._held)
        self.count.setText(f"  {n} request{'s' if n != 1 else ''} held" if n else "  Waiting for requests…")
        for b in (self.b_forward, self.b_drop, self.b_rep, self.b_intr, self.b_all):
            b.setEnabled(bool(n))
        if not n:
            self.method.setCurrentText("GET")
            for w in (self.url, self.headers, self.body):
                w.clear()

    def _show(self, row: int):
        if not (0 <= row < len(self._held)):
            return
        r = self._held[row]
        self.method.setCurrentText(r["method"])
        self.url.setText(r["url"])
        self.headers.setPlainText("\n".join(f"{k}: {v}" for k, v in r["headers"].items()))
        self.body.setPlainText(r["body"].decode("utf-8", "replace") if r["body"] else "")

    def _current(self) -> int:
        return self.queue.currentRow()

    def _edited(self) -> dict:
        hdrs = {}
        for line in self.headers.toPlainText().splitlines():
            if ":" in line:
                k, _, val = line.partition(":")
                if k.strip():
                    hdrs[k.strip()] = val.strip()
        return {"method": self.method.currentText().strip().upper() or "GET", "url": self.url.text().strip(),
                "headers": hdrs, "body": self.body.toPlainText().encode("utf-8")}

    def _take(self, row: int) -> dict:
        r = self._held.pop(row)
        self.queue.takeItem(row)
        if self._held:
            self.queue.setCurrentRow(min(row, len(self._held) - 1))
        self._refresh()
        return r

    # ---------------------------------------------------------------- actions
    def forward(self):
        row = self._current()
        if row < 0:
            return
        edited = self._edited()
        r = self._take(row)
        self._send(r["view"], edited)

    def forward_all(self):
        if self._current() >= 0:
            self.forward()
        while self._held:
            r = self._take(0)
            self._send(r["view"], r)

    def drop(self):
        row = self._current()
        if row >= 0:
            r = self._take(row)
            self.win.toast(f"Dropped {r['method']} {r['url']}", 4000)

    def to_repeater(self):
        if self._current() >= 0:
            e = self._edited()
            self.win.security.tools_tab.load_request(e["method"], e["url"], e["headers"], e["body"].decode("utf-8", "replace"))
            self.win.security.show()
            self.win.security.show_tab("Tools")

    def to_intruder(self):
        if self._current() >= 0:
            e = self._edited()
            self.win.security.intruder.load_request(e["method"], e["url"], e["headers"], e["body"].decode("utf-8", "replace"))
            self.win.security.show()
            self.win.security.show_tab("Intruder")

    def _send(self, view, r: dict):
        """Load exactly this request in its tab (once, without holding it again)."""
        from PySide6.QtWebEngineCore import QWebEngineHttpRequest
        try:
            if view is None or self.win._index_of(view) < 0:
                self.win.toast("That tab was closed; the request was not sent.", 5000)
                return
        except RuntimeError:
            return
        url = QUrl(r["url"])
        if not url.isValid() or url.scheme() not in ("http", "https"):
            self.win.toast(f"Not a valid http(s) URL: {r['url']}", 5000)
            return
        req = QWebEngineHttpRequest(url)
        try:
            req.setMethod(QWebEngineHttpRequest.Method.Post if r["method"] == "POST" else QWebEngineHttpRequest.Method.Get)
        except Exception:  # noqa: BLE001
            pass
        for k, val in r["headers"].items():
            if k.lower() not in _SKIP:
                req.setHeader(QByteArray(k.encode()), QByteArray(val.encode()))
        if r["method"] == "POST" and r["body"]:
            req.setPostData(QByteArray(r["body"]))
        if r["method"] not in ("GET", "POST"):
            self.win.toast(f"The browser can only load GET and POST pages; sending {r['method']} via Repeater.", 6000)
            self.win.security.tools_tab.load_request(r["method"], r["url"], r["headers"], r["body"].decode("utf-8", "replace"))
            self.win.security.show_tab("Tools")
            return
        self.win._intercept_pass.add(url.toString())
        view.load(req)

    def _toggled(self, on: bool):
        self.win.set_intercept(on)
        self.toggle.setText("Intercept is ON" if on else "Intercept is OFF")
        if not on:
            self.forward_all()

    def closeEvent(self, e):
        if self.win.intercept_on:
            self.toggle.setChecked(False)  # closing the window turns Intercept off and releases what's held
        super().closeEvent(e)


def held_page(url: str) -> str:
    """Shown in the tab while its request waits in the Intercept window."""
    return (f"<html><body style='font-family:sans-serif;background:#111418;color:#e6e8eb;padding:48px'>"
            f"<h2 style='color:#ff7a1a'>Request held by Intercept</h2><p>{escape(url)}</p>"
            "<p style='color:#9aa3ad'>Edit it in the Intercept window, then <b>Forward</b> to load it here, or "
            "<b>Drop</b> it.</p></body></html>")
