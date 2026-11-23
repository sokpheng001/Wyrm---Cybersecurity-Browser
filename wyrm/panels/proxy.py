#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/proxy.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Developers: @kwan and @oda (intercepting HTTPS proxy)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Proxy tab: full HTTPS request/response history (with bodies) and response interception (hold → edit → forward)."""
from __future__ import annotations

import collections
import threading
from html import escape

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QHBoxLayout, QLabel, QLineEdit, QMenu, QPlainTextEdit, QPushButton,
                               QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..security import mitm
from .common import mono


class ProxyTab(QWidget):
    """Burp/Caido-style proxy history + response interception, backed by wyrm/security/mitm.py."""

    _flow = Signal(object)
    _hold = Signal(int, object)
    _hold_req = Signal()

    def __init__(self, win):
        super().__init__()
        self.win = win
        self._held: dict = {}      # id -> {"event", "result"}
        self._held_seq = 0
        self._held_current = None  # id of the flow shown for editing
        # request interception queue (hold → edit → forward/drop every request, Burp/Caido-style)
        self._req_holds: dict = {}
        self._req_order = collections.deque()
        self._req_lock = threading.Lock()
        self._req_showing = None
        self._flow.connect(self._on_flow)
        self._hold.connect(self._on_hold)
        self._hold_req.connect(self._show_next_req)
        v = QVBoxLayout(self)

        active = mitm.ACTIVE is not None
        intro = QLabel()
        intro.setWordWrap(True)
        if active:
            intro.setText("<b>Proxy</b> — every request and response flows through Wyrm's intercepting proxy; full "
                          "messages (with bodies) are captured below. Turn on <b>Intercept requests</b> to pause, "
                          "edit or drop every request (XHR and API calls too) before it is sent, or <b>Intercept "
                          "responses</b> to edit a response before the page sees it.")
        else:
            intro.setText("<b>Proxy</b> — the intercepting HTTPS proxy is <b>off</b>. Turn it on to capture full "
                          "request/response bodies and edit responses (Burp/Caido-style). It installs a local "
                          "certificate so HTTPS can be decrypted, and restarts Wyrm.")
        v.addWidget(intro)

        row = QHBoxLayout()
        self.toggle = QPushButton("Turn off proxy" if active else "Turn on intercepting proxy")
        self.toggle.setObjectName("Primary")
        self.toggle.clicked.connect(lambda: self.win.set_mitm_enabled(not active))
        row.addWidget(self.toggle)
        self.intercept_req = QCheckBox("Intercept requests")
        self.intercept_req.setEnabled(active)
        self.intercept_req.setToolTip("Hold every request (including XHR / API calls) so you can edit or drop it "
                                      "before it is sent — the core Burp/Caido loop.")
        self.intercept_req.toggled.connect(lambda on: setattr(self, "_intercept_req_on", on))
        row.addWidget(self.intercept_req)
        self.intercept = QCheckBox("Intercept responses")
        self.intercept.setEnabled(active)
        self.intercept.toggled.connect(self._set_intercept)
        row.addWidget(self.intercept)
        from PySide6.QtCore import QSettings
        self.http2_cb = QCheckBox("HTTP/2 (experimental)")
        self.http2_cb.setToolTip("Negotiate and intercept HTTP/2 (h2) as well as HTTP/1.1. Experimental — applies "
                                 "after you restart Wyrm.")
        self.http2_cb.setChecked(QSettings().value("mitm/http2", False, type=bool))
        self.http2_cb.setEnabled(active)
        self.http2_cb.toggled.connect(self._set_http2)
        row.addWidget(self.http2_cb)
        row.addStretch(1)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Search URL, method, status, headers, body…")
        self.filter.textChanged.connect(self._apply_filter)
        row.addWidget(self.filter, 1)
        clear = QPushButton("Clear")
        clear.clicked.connect(self._clear)
        row.addWidget(clear)
        v.addLayout(row)

        split = QSplitter(Qt.Orientation.Vertical)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Time", "Method", "Status", "URL"])
        self.tree.setRootIsDecorated(False)
        self.tree.setColumnWidth(0, 70)
        self.tree.setColumnWidth(1, 60)
        self.tree.setColumnWidth(2, 55)
        self.tree.currentItemChanged.connect(self._show)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        split.addWidget(self.tree)
        pair = QSplitter(Qt.Orientation.Horizontal)
        self.req = mono(QPlainTextEdit())
        self.req.setReadOnly(True)
        self.resp = mono(QPlainTextEdit())  # editable when a response is held
        self.resp.setReadOnly(True)
        pair.addWidget(self.req)
        pair.addWidget(self.resp)
        split.addWidget(pair)
        split.setSizes([260, 320])
        v.addWidget(split, 1)

        self.hold_bar = QWidget()
        hb = QHBoxLayout(self.hold_bar)
        hb.setContentsMargins(0, 0, 0, 0)
        self.hold_lbl = QLabel("")
        self.hold_lbl.setObjectName("Muted")
        hb.addWidget(self.hold_lbl, 1)
        self.b_forward = QPushButton("Forward (edited)")
        self.b_forward.setObjectName("Primary")
        self.b_forward.clicked.connect(self._forward)
        self.b_drop = QPushButton("Forward unchanged")
        self.b_drop.clicked.connect(lambda: self._forward(unchanged=True))
        hb.addWidget(self.b_drop)
        hb.addWidget(self.b_forward)
        v.addWidget(self.hold_bar)
        self.hold_bar.hide()

        self.req_hold_bar = QWidget()
        rb = QHBoxLayout(self.req_hold_bar)
        rb.setContentsMargins(0, 0, 0, 0)
        self.req_hold_lbl = QLabel("")
        self.req_hold_lbl.setObjectName("Muted")
        rb.addWidget(self.req_hold_lbl, 1)
        self.rb_drop = QPushButton("Drop")
        self.rb_drop.clicked.connect(lambda: self._forward_req(drop=True))
        self.rb_repeater = QPushButton("Send to Repeater")
        self.rb_repeater.clicked.connect(self._held_to_repeater)
        self.rb_forward = QPushButton("Forward")
        self.rb_forward.setObjectName("Primary")
        self.rb_forward.clicked.connect(lambda: self._forward_req())
        rb.addWidget(self.rb_drop)
        rb.addWidget(self.rb_repeater)
        rb.addWidget(self.rb_forward)
        v.addWidget(self.req_hold_bar)
        self.req_hold_bar.hide()

        if active:
            mitm.ACTIVE.on_flow = lambda fl: self._flow.emit(fl)
            mitm.ACTIVE.edit_response = self._edit_response
            mitm.ACTIVE.intercept_request = self._edit_request
            for fl in list(mitm.ACTIVE.flows):   # history captured before the panel opened
                self._on_flow(fl)

    # ------------------------------------------------------------ interception plumbing (worker thread)
    def _set_intercept(self, on):
        self._intercept_on = on

    def _set_http2(self, on):
        from PySide6.QtCore import QSettings
        QSettings().setValue("mitm/http2", on)
        self.win.toast(f"HTTP/2 interception {'enabled' if on else 'disabled'} — restart Wyrm to apply.", 6000)

    def _edit_response(self, flow):
        """Runs on a proxy worker thread; blocks until the user forwards (or a timeout)."""
        if not getattr(self, "_intercept_on", False):
            return None
        self._held_seq += 1
        hid = self._held_seq
        ev = threading.Event()
        self._held[hid] = {"event": ev, "result": None}
        self._hold.emit(hid, flow)
        if not ev.wait(120):
            self._held.pop(hid, None)
            return None
        slot = self._held.pop(hid, None)
        return slot["result"] if slot else None

    # ------------------------------------------------------------ UI (main thread)
    def _on_flow(self, fl):
        it = QTreeWidgetItem([fl.get("time", ""), fl.get("method", ""), str(fl.get("status", "")),
                              fl.get("url", "")[:300]])
        it.setData(0, Qt.ItemDataRole.UserRole, fl)
        self.tree.addTopLevelItem(it)
        self._filter_item(it)
        bar = self.tree.verticalScrollBar()
        follow = bar.value() >= bar.maximum() - 4
        if self.tree.topLevelItemCount() == 1:
            self.tree.setCurrentItem(it)
        if follow:
            self.tree.scrollToBottom()

    def _on_hold(self, hid, fl):
        self._held_current = hid
        # select/refresh the detail with an editable response body
        it = QTreeWidgetItem([fl.get("time", ""), fl.get("method", ""), "HELD", fl.get("url", "")[:300]])
        it.setData(0, Qt.ItemDataRole.UserRole, fl)
        self.tree.addTopLevelItem(it)
        self.tree.setCurrentItem(it)
        self.resp.setReadOnly(False)
        self.hold_lbl.setText(f"Response held: {fl.get('method')} {fl.get('url','')[:60]} — edit the body and forward")
        self.hold_bar.show()
        self.win.security.show()
        self.win.security.show_tab("Proxy")

    def _forward(self, unchanged=False):
        hid = self._held_current
        if hid is None:
            return
        result = None
        if not unchanged:
            fl = None
            it = self.tree.currentItem()
            if it:
                fl = it.data(0, Qt.ItemDataRole.UserRole)
            body = self.resp.toPlainText().encode("utf-8", "replace")
            status = fl.get("status", 200) if fl else 200
            headers = [(k, v) for k, v in (fl.get("resp_headers", []) if fl else [])
                       if k.lower() not in ("content-length", "content-encoding", "transfer-encoding")]
            result = (status, headers, body)
        slot = self._held.get(hid)
        if slot:
            slot["result"] = result
            slot["event"].set()
        self._held_current = None
        self.hold_bar.hide()
        self.resp.setReadOnly(True)

    # ------------------------------------------------------------ request interception (worker thread → UI queue)
    def _edit_request(self, req):
        """Runs on a proxy worker thread; blocks until the user forwards/drops this request (or a timeout)."""
        if not getattr(self, "_intercept_req_on", False):
            return True
        self._held_seq += 1
        hid = self._held_seq
        ev = threading.Event()
        with self._req_lock:
            self._req_holds[hid] = {"event": ev, "req": req, "keep": True}
            self._req_order.append(hid)
        self._hold_req.emit()
        if not ev.wait(300):   # 5 min: forward on timeout so the browser never hangs forever
            with self._req_lock:
                self._req_holds.pop(hid, None)
            return True
        with self._req_lock:
            slot = self._req_holds.pop(hid, None)
        return slot["keep"] if slot else True

    def _show_next_req(self):
        """Present the next held request for editing (one at a time; the rest wait in the queue)."""
        if self._req_showing is not None:
            return
        with self._req_lock:
            nxt = None
            while self._req_order:
                hid = self._req_order.popleft()
                if hid in self._req_holds:
                    nxt = hid
                    break
            self._req_showing = nxt
            queued = len(self._req_order)
        if self._req_showing is None:
            return
        slot = self._req_holds.get(self._req_showing)
        if not slot:
            self._req_showing = None
            return
        req = slot["req"]
        self.req.setReadOnly(False)
        self.req.setPlainText(_req_text(req))
        self.resp.clear()
        self.req_hold_lbl.setText(f"REQUEST HELD — {req['method']} {req['host']}{req['path']}"
                                  + (f"   (+{queued} queued)" if queued else "") + " — edit and Forward, or Drop")
        self.req_hold_bar.show()
        self.win.security.show()
        self.win.security.show_tab("Proxy")

    def _forward_req(self, drop=False):
        hid = self._req_showing
        if hid is None:
            return
        with self._req_lock:
            slot = self._req_holds.get(hid)
        if slot:
            if drop:
                slot["keep"] = False
            else:
                _apply_req_edit(slot["req"], self.req.toPlainText())
                slot["keep"] = True
            slot["event"].set()
        self._req_showing = None
        self.req.setReadOnly(True)
        self.req_hold_bar.hide()
        self._show_next_req()

    def _held_to_repeater(self):
        """Copy the held request into Repeater (then forward it unchanged so the page keeps working)."""
        hid = self._req_showing
        slot = self._req_holds.get(hid) if hid is not None else None
        if not slot:
            return
        req = dict(slot["req"])
        _apply_req_edit(req, self.req.toPlainText())
        url = f"{req['scheme']}://{req['host']}{req['path']}"
        self.win.security.tools_tab.load_request(req["method"], url, dict(req["headers"]),
                                                 _as_text(req.get("body", b"")))
        self._forward_req()  # let the live request through unchanged
        self.win.security.show_tab("Tools")

    def _show(self, it, _prev=None):
        if self._req_showing is not None:   # a held request is being edited: don't clobber the editor
            return
        fl = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not fl:
            self.req.clear()
            self.resp.clear()
            return
        rq = [f"{fl.get('method')} {fl.get('path', fl.get('url', ''))}"]
        rq += [f"{k}: {v}" for k, v in fl.get("req_headers", [])]
        if fl.get("req_body"):
            rq.append("")
            rq.append(_as_text(fl["req_body"]))
        self.req.setPlainText("\n".join(rq))
        rs = [f"HTTP {fl.get('status', '')}"]
        rs += [f"{k}: {v}" for k, v in fl.get("resp_headers", [])]
        rs.append("")
        rs.append(mitm.decode_body(fl.get("resp_headers", []), fl.get("resp_body", b"")))
        self.resp.setPlainText("\n".join(rs) if self._held_current is None
                               else mitm.decode_body(fl.get("resp_headers", []), fl.get("resp_body", b"")))

    def _menu(self, pos):
        it = self.tree.itemAt(pos)
        fl = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not fl:
            return
        m = QMenu(self)
        m.addAction("Send to Repeater", lambda: self._to_repeater(fl))
        m.addAction("Send to Intruder", lambda: self._to_intruder(fl))
        m.addAction("Send to Session macro", lambda: self._to_session(fl))
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _to_repeater(self, fl):
        self.win.security.tools_tab.load_request(fl.get("method", "GET"), fl.get("url", ""),
                                                 dict(fl.get("req_headers", [])), _as_text(fl.get("req_body", b"")))
        self.win.security.show_tab("Tools")

    def _to_intruder(self, fl):
        self.win.security.intruder.load_request(fl.get("method", "GET"), fl.get("url", ""),
                                                dict(fl.get("req_headers", [])), _as_text(fl.get("req_body", b"")))
        self.win.security.show_tab("Intruder")

    def _to_session(self, fl):
        self.win.security.sessionauth.load_macro(fl.get("method", "POST"), fl.get("url", ""),
                                                 dict(fl.get("req_headers", [])), _as_text(fl.get("req_body", b"")))
        self.win.security.show_tab("Session / auth")

    def _apply_filter(self):
        for i in range(self.tree.topLevelItemCount()):
            self._filter_item(self.tree.topLevelItem(i))

    def _filter_item(self, it):
        f = self.filter.text().strip().lower()
        if not f:
            it.setHidden(False)
            return
        hay = it.data(0, Qt.ItemDataRole.UserRole + 1)   # full-text haystack, built once per flow and cached
        if hay is None:
            fl = it.data(0, Qt.ItemDataRole.UserRole) or {}
            parts = [fl.get("url", ""), fl.get("method", ""), str(fl.get("status", "")),
                     _as_text(fl.get("req_body", b""))]
            parts += [f"{k}: {v}" for k, v in fl.get("req_headers", [])]
            parts += [f"{k}: {v}" for k, v in fl.get("resp_headers", [])]
            try:
                parts.append(mitm.decode_body(fl.get("resp_headers", []), fl.get("resp_body", b"")))
            except Exception:  # noqa: BLE001
                pass
            hay = " ".join(parts).lower()
            it.setData(0, Qt.ItemDataRole.UserRole + 1, hay)
        it.setHidden(f not in hay)

    def _clear(self):
        self.tree.clear()
        self.req.clear()
        self.resp.clear()
        if mitm.ACTIVE is not None:
            mitm.ACTIVE.flows.clear()


def _as_text(b) -> str:
    if isinstance(b, bytes):
        return b.decode("utf-8", "replace")
    return str(b or "")


def _req_text(req) -> str:
    lines = [f"{req['method']} {req['path']}"]
    lines += [f"{k}: {v}" for k, v in req["headers"]]
    lines.append("")
    lines.append(_as_text(req.get("body", b"")))
    return "\n".join(lines)


def _apply_req_edit(req, text):
    """Parse an edited raw request (first line + headers + blank line + body) back into the req dict."""
    lines = text.split("\n")
    first = lines[0].strip() if lines else ""
    parts = first.split(" ", 1)
    if parts and parts[0]:
        req["method"] = parts[0].strip()
    if len(parts) > 1 and parts[1].strip():
        req["path"] = parts[1].strip()
    headers, i = [], 1
    while i < len(lines) and lines[i].strip() != "":
        if ":" in lines[i]:
            k, _, val = lines[i].partition(":")
            if k.strip() and k.strip().lower() != "content-length":   # let the client set Content-Length
                headers.append((k.strip(), val.strip()))
        i += 1
    req["headers"] = headers
    body = "\n".join(lines[i + 1:]) if i + 1 <= len(lines) else ""
    req["body"] = body.encode("utf-8", "replace")
