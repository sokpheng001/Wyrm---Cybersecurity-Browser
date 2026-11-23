#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/wsintercept.py
# Developers: Kwan and Oda (intercepting HTTPS proxy — WebSocket frames)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""WebSocket tab: live view of every WebSocket frame, with frame editing (hold → edit → forward / drop).

Backed by wyrm/security/mitm.py: registering a frame hook makes the proxy parse WebSocket connections frame by
frame instead of blind-relaying them, so this works for wss:// (TLS) traffic, Burp/Caido-style.
"""
from __future__ import annotations

import threading
from html import escape

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QCheckBox, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit, QPushButton,
                               QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..security import mitm
from .common import mono

ARROW = {"out": "▲ to server", "in": "▼ to page"}


class WsTab(QWidget):
    """Live WebSocket frames + frame interception, backed by the intercepting proxy."""

    _frame = Signal(object)
    _hold = Signal(int, object)

    def __init__(self, win):
        super().__init__()
        self.win = win
        self._held: dict = {}
        self._held_seq = 0
        self._held_current = None
        self._frame.connect(self._on_frame)
        self._hold.connect(self._on_hold)
        v = QVBoxLayout(self)

        active = mitm.ACTIVE is not None
        intro = QLabel()
        intro.setWordWrap(True)
        if active:
            intro.setText("<b>WebSocket</b> — every WebSocket frame (even over <b>wss://</b> TLS) is shown below. "
                          "Turn on <b>Intercept frames</b> to pause a text frame, edit its payload and forward it, "
                          "forward it unchanged, or drop it.")
        else:
            intro.setText("<b>WebSocket</b> — turn on the <b>intercepting proxy</b> (Proxy tab) to capture and edit "
                          "WebSocket frames. Wyrm then decodes each frame so you can read and rewrite it.")
        v.addWidget(intro)

        row = QHBoxLayout()
        self.intercept = QCheckBox("Intercept frames")
        self.intercept.setEnabled(active)
        self.intercept.toggled.connect(lambda on: setattr(self, "_intercept_on", on))
        row.addWidget(self.intercept)
        row.addStretch(1)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter…")
        self.filter.textChanged.connect(self._apply_filter)
        row.addWidget(self.filter, 1)
        clear = QPushButton("Clear")
        clear.clicked.connect(self._clear)
        row.addWidget(clear)
        v.addLayout(row)

        split = QSplitter(Qt.Orientation.Vertical)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Time", "Direction", "Type", "Payload"])
        self.tree.setRootIsDecorated(False)
        self.tree.setColumnWidth(0, 70)
        self.tree.setColumnWidth(1, 90)
        self.tree.setColumnWidth(2, 60)
        self.tree.currentItemChanged.connect(self._show)
        split.addWidget(self.tree)
        self.editor = mono(QPlainTextEdit())
        self.editor.setReadOnly(True)
        split.addWidget(self.editor)
        split.setSizes([300, 220])
        v.addWidget(split, 1)

        self.hold_bar = QWidget()
        hb = QHBoxLayout(self.hold_bar)
        hb.setContentsMargins(0, 0, 0, 0)
        self.hold_lbl = QLabel("")
        self.hold_lbl.setObjectName("Muted")
        hb.addWidget(self.hold_lbl, 1)
        self.b_drop = QPushButton("Drop")
        self.b_drop.clicked.connect(lambda: self._forward(drop=True))
        self.b_unchanged = QPushButton("Forward unchanged")
        self.b_unchanged.clicked.connect(lambda: self._forward(unchanged=True))
        self.b_forward = QPushButton("Forward (edited)")
        self.b_forward.setObjectName("Primary")
        self.b_forward.clicked.connect(lambda: self._forward())
        hb.addWidget(self.b_drop)
        hb.addWidget(self.b_unchanged)
        hb.addWidget(self.b_forward)
        v.addWidget(self.hold_bar)
        self.hold_bar.hide()

        if active:
            mitm.ACTIVE.on_ws = lambda fr: self._frame.emit(fr)
            mitm.ACTIVE.edit_ws = self._edit_ws
            for fr in list(mitm.ACTIVE.ws_flows):
                self._on_frame(fr)

    # ------------------------------------------------------------ interception (worker thread)
    def _edit_ws(self, frame):
        """Runs on a proxy worker thread. Only text frames are held for editing; others pass through."""
        if not getattr(self, "_intercept_on", False) or frame.get("opcode") != 0x1:
            return None
        self._held_seq += 1
        hid = self._held_seq
        ev = threading.Event()
        self._held[hid] = {"event": ev, "result": None}
        self._hold.emit(hid, frame)
        if not ev.wait(120):
            self._held.pop(hid, None)
            return None
        slot = self._held.pop(hid, None)
        return slot["result"] if slot else None

    # ------------------------------------------------------------ UI (main thread)
    def _preview(self, fr) -> str:
        p = fr.get("payload", b"")
        if fr.get("opcode") == 0x1:
            return p.decode("utf-8", "replace")
        return f"<{len(p)} bytes> " + p[:48].hex(" ")

    def _on_frame(self, fr):
        it = QTreeWidgetItem([fr.get("time", ""), ARROW.get(fr.get("dir"), fr.get("dir", "")),
                              fr.get("opname", ""), self._preview(fr)[:300]])
        it.setData(0, Qt.ItemDataRole.UserRole, fr)
        self.tree.addTopLevelItem(it)
        self._filter_item(it)
        bar = self.tree.verticalScrollBar()
        follow = bar.value() >= bar.maximum() - 4
        if self.tree.topLevelItemCount() == 1:
            self.tree.setCurrentItem(it)
        if follow:
            self.tree.scrollToBottom()

    def _on_hold(self, hid, fr):
        self._held_current = hid
        it = QTreeWidgetItem([fr.get("time", ""), ARROW.get(fr.get("dir"), ""), "HELD", self._preview(fr)[:300]])
        it.setData(0, Qt.ItemDataRole.UserRole, fr)
        self.tree.addTopLevelItem(it)
        self.tree.setCurrentItem(it)
        self.editor.setReadOnly(False)
        self.editor.setPlainText(fr.get("payload", b"").decode("utf-8", "replace"))
        self.hold_lbl.setText(f"Frame held ({ARROW.get(fr.get('dir'), '')}) — edit the payload and forward")
        self.hold_bar.show()
        self.win.security.show()
        self.win.security.show_tab("WebSocket")

    def _forward(self, unchanged=False, drop=False):
        hid = self._held_current
        if hid is None:
            return
        if drop:
            result = False
        elif unchanged:
            result = None
        else:
            result = self.editor.toPlainText().encode("utf-8", "replace")
        slot = self._held.get(hid)
        if slot:
            slot["result"] = result
            slot["event"].set()
        self._held_current = None
        self.hold_bar.hide()
        self.editor.setReadOnly(True)

    def _show(self, it, _prev=None):
        fr = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not fr:
            self.editor.clear()
            return
        if self._held_current is None:
            p = fr.get("payload", b"")
            text = p.decode("utf-8", "replace") if fr.get("opcode") == 0x1 else \
                f"[{fr.get('opname')}] {len(p)} bytes\n\n" + _hexdump(p)
            self.editor.setReadOnly(True)
            self.editor.setPlainText(text)

    def _apply_filter(self):
        for i in range(self.tree.topLevelItemCount()):
            self._filter_item(self.tree.topLevelItem(i))

    def _filter_item(self, it):
        f = self.filter.text().strip().lower()
        if not f:
            it.setHidden(False)
            return
        hay = " ".join(it.text(c) for c in range(4)).lower()
        it.setHidden(f not in hay)

    def _clear(self):
        self.tree.clear()
        self.editor.clear()
        if mitm.ACTIVE is not None:
            mitm.ACTIVE.ws_flows.clear()


def _hexdump(b: bytes, limit: int = 2048) -> str:
    b = b[:limit]
    lines = []
    for i in range(0, len(b), 16):
        chunk = b[i:i + 16]
        hexs = " ".join(f"{x:02x}" for x in chunk)
        text = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        lines.append(f"{i:08x}  {hexs:<47}  {text}")
    return "\n".join(lines)
