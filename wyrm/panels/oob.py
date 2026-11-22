#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/oob.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Developer: @kwan (out-of-band interaction listener)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""OOB Interactions tab: start a callback listener, copy a unique payload URL, watch incoming hits."""
from __future__ import annotations

from html import escape

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTextBrowser, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from ..security import oob
from .common import mono


class OobTab(QWidget):
    """Collaborator-style out-of-band interaction catcher."""

    _hit = Signal(object)  # from the server thread -> UI thread

    def __init__(self, win):
        super().__init__()
        self.win = win
        self.server = None
        self.hits: list = []
        self._hit.connect(self._on_hit)
        v = QVBoxLayout(self)

        intro = QLabel("<b>OOB Interactions</b> — confirm <b>blind</b> bugs (blind SSRF, blind XSS, SSTI, XXE, "
                       "command injection). Start the listener, inject the URL below into a target, and watch for "
                       "callbacks here. Only test systems you're authorized to test.")
        intro.setWordWrap(True)
        v.addWidget(intro)

        row = QHBoxLayout()
        self.toggle = QPushButton("Start listener")
        self.toggle.setObjectName("Primary")
        self.toggle.clicked.connect(self._toggle)
        row.addWidget(self.toggle)
        row.addWidget(QLabel("Reachable address"))
        self.host = QComboBox()
        self.host.setEditable(True)
        self.host.setMinimumWidth(150)
        row.addWidget(self.host, 1)
        v.addLayout(row)

        pay = QHBoxLayout()
        pay.addWidget(QLabel("Payload URL"))
        self.payload = mono(QLineEdit())
        self.payload.setReadOnly(True)
        self.payload.setPlaceholderText("Start the listener to generate a URL")
        pay.addWidget(self.payload, 1)
        self.b_new = QPushButton("New URL")
        self.b_new.clicked.connect(self._new_payload)
        self.b_new.setEnabled(False)
        pay.addWidget(self.b_new)
        self.b_copy = QPushButton("Copy")
        self.b_copy.clicked.connect(lambda: QGuiApplication.clipboard().setText(self.payload.text()))
        self.b_copy.setEnabled(False)
        pay.addWidget(self.b_copy)
        v.addLayout(pay)

        self.status = QLabel("Listener off.")
        self.status.setObjectName("Muted")
        self.status.setWordWrap(True)
        v.addWidget(self.status)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Time", "Source IP", "Method", "Path"])
        self.tree.setRootIsDecorated(False)
        self.tree.currentItemChanged.connect(self._show)
        self.tree.header().setStretchLastSection(True)
        v.addWidget(self.tree, 2)
        self.detail = mono(QTextBrowser())
        v.addWidget(self.detail, 1)

    # ------------------------------------------------------------ listener
    def _toggle(self):
        if self.server is not None:
            self.server.stop()
            self.server = None
            self.toggle.setText("Start listener")
            self.b_new.setEnabled(False)
            self.b_copy.setEnabled(False)
            self.status.setText("Listener off.")
            return
        port = self.win.settings.value("oob/port", 0, type=int)
        self.server = oob.InteractionServer(lambda h: self._hit.emit(h))
        if not self.server.start(port):
            self.server = None
            self.status.setText("Could not start the listener (port in use?). Set a different port in Settings.")
            return
        self.host.clear()
        self.host.addItems(oob.local_ips() or ["127.0.0.1"])
        self.toggle.setText("Stop listener")
        self.b_new.setEnabled(True)
        self.b_copy.setEnabled(True)
        self._new_payload()
        self.status.setText(f"Listening on port {self.server.port} (all interfaces). Pick the address a target can "
                            "reach you at. For internet targets, run Wyrm on a public IP or port-forward this port.")

    def _new_payload(self):
        if self.server is None:
            return
        host = self.host.currentText().strip() or "127.0.0.1"
        tok = oob.InteractionServer.new_token()
        self._token = tok
        self.payload.setText(f"http://{host}:{self.server.port}/{tok}")

    def _on_hit(self, hit):
        self.hits.insert(0, hit)
        it = QTreeWidgetItem([hit["time"], hit["ip"], hit["method"], hit["path"][:60]])
        self.tree.insertTopLevelItem(0, it)
        it.setData(0, Qt.ItemDataRole.UserRole, hit)
        if self.tree.currentItem() is None:
            self.tree.setCurrentItem(it)
        self.win.toast(f"OOB callback from {hit['ip']} → {hit['path'][:40]}", 6000)

    def _show(self, it, _prev=None):
        hit = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not hit:
            self.detail.clear()
            return
        hdrs = "".join(f"{escape(k)}: {escape(v)}\n" for k, v in hit["headers"].items())
        self.detail.setPlainText(f"{hit['method']} {hit['path']}\nFrom: {hit['ip']}   {hit['time']}\n\n"
                                 f"{hdrs}\n{hit['body']}")

    def shutdown(self):
        if self.server is not None:
            self.server.stop()
            self.server = None
