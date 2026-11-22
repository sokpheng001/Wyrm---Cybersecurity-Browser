#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/capture.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Developer: @kwan (in-page API & WebSocket capture)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""API & WebSocket tab: live fetch/XHR calls (with bodies) and WebSocket frames captured from pages."""
from __future__ import annotations

from urllib.parse import urlparse

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QCheckBox, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from .common import mono


class CaptureTab(QWidget):
    """Shows fetch/XHR API calls (request + response bodies) and WebSocket frames from the pages you browse."""

    def __init__(self, win):
        super().__init__()
        self.win = win
        v = QVBoxLayout(self)
        intro = QLabel("<b>API &amp; WebSocket</b> — captures <b>fetch</b> / <b>XHR</b> calls (with request and "
                       "response bodies) and <b>WebSocket</b> frames from the pages you browse, no proxy needed. "
                       "Top-level pages and static files aren't included (that needs a proxy).")
        intro.setWordWrap(True)
        v.addWidget(intro)

        row = QHBoxLayout()
        self.enable = QCheckBox("Capture API & WebSocket traffic")
        self.enable.setChecked(self.win.capture_enabled())
        self.enable.toggled.connect(self.win.set_capture_enabled)
        row.addWidget(self.enable)
        row.addStretch(1)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter by URL…")
        self.filter.textChanged.connect(self._apply_filter)
        row.addWidget(self.filter, 1)
        clear = QPushButton("Clear")
        clear.clicked.connect(self._clear)
        row.addWidget(clear)
        v.addLayout(row)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Type", "Method/Event", "URL", "Status"])
        self.tree.setRootIsDecorated(False)
        self.tree.header().setStretchLastSection(False)
        self.tree.setColumnWidth(0, 60)
        self.tree.setColumnWidth(1, 90)
        self.tree.setColumnWidth(2, 360)
        self.tree.currentItemChanged.connect(self._show)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.customContextMenuRequested.connect(self._menu)
        v.addWidget(self.tree, 2)

        self.detail = mono(self._browser())
        v.addWidget(self.detail, 1)
        for rec in getattr(self.win, "captures", []):
            self.add_record(rec)

    @staticmethod
    def _browser():
        from PySide6.QtWidgets import QTextBrowser
        return QTextBrowser()

    def add_record(self, rec):
        k = rec.get("k", "")
        if k == "ws":
            method, status = rec.get("ev", ""), ""
        else:
            method, status = rec.get("method", ""), str(rec.get("status", ""))
        it = QTreeWidgetItem([{"fetch": "fetch", "xhr": "XHR", "ws": "WS"}.get(k, k), method,
                              rec.get("url", "")[:200], status])
        it.setData(0, Qt.ItemDataRole.UserRole, rec)
        self.tree.addTopLevelItem(it)
        self._filter_item(it)
        if self.tree.topLevelItemCount() == 1:
            self.tree.setCurrentItem(it)
        bar = self.tree.verticalScrollBar()
        if bar.value() >= bar.maximum() - 4:
            self.tree.scrollToBottom()

    def _show(self, it, _prev=None):
        rec = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not rec:
            self.detail.clear()
            return
        lines = [f"{rec.get('method', rec.get('ev', ''))}  {rec.get('url', '')}"]
        if rec.get("status"):
            lines.append(f"Status: {rec['status']}")
        if rec.get("req"):
            lines.append("\n--- Request body ---\n" + rec["req"])
        if rec.get("res"):
            label = "Frame" if rec.get("k") == "ws" else "Response body"
            lines.append(f"\n--- {label} ---\n" + rec["res"])
        self.detail.setPlainText("\n".join(lines))

    def _menu(self, pos):
        it = self.tree.itemAt(pos)
        rec = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not rec or rec.get("k") == "ws":
            return
        m = QMenu(self)
        m.addAction("Send to Repeater", lambda: self._to_repeater(rec))
        m.exec(self.tree.viewport().mapToGlobal(pos))

    def _to_repeater(self, rec):
        self.win.security.tools_tab.load_request(rec.get("method", "GET"), rec.get("url", ""), {},
                                                 rec.get("req", ""))
        self.win.security.show_tab("Tools")

    def _apply_filter(self):
        for i in range(self.tree.topLevelItemCount()):
            self._filter_item(self.tree.topLevelItem(i))

    def _filter_item(self, it):
        f = self.filter.text().strip().lower()
        it.setHidden(bool(f) and f not in (it.data(0, Qt.ItemDataRole.UserRole).get("url", "").lower()))

    def _clear(self):
        self.tree.clear()
        self.detail.clear()
        if hasattr(self.win, "captures"):
            self.win.captures.clear()
