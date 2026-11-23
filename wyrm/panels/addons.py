#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/addons.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Security panel → Add-ons: install, enable/disable and inspect Wyrm add-ons (Python plugins).

Add-ons are trusted in-process code, so enabling one shows a warning first (like installing a browser extension).
Enabling/disabling and installing take effect after a restart, because add-ons load at startup.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPlainTextEdit, QPushButton,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..addons import loader
from ..ui.dialogs import security_warning
from .common import mono


class AddonsTab(QWidget):
    """Manage Wyrm add-ons: a list with enable/disable, install-from-folder, open folder, and logs."""

    def __init__(self, win):
        super().__init__()
        self.win = win
        v = QVBoxLayout(self)
        intro = QLabel(
            "<b>Add-ons</b> — extend Wyrm with Python plugins (rewrite traffic, add tabs, file findings), like "
            "Burp BApps / Caido plugins. Add-ons are <b>trusted code</b> that runs inside Wyrm, so only enable ones "
            "you trust. Enabling, disabling or installing an add-on takes effect after you restart Wyrm.")
        intro.setWordWrap(True)
        v.addWidget(intro)

        row = QHBoxLayout()
        b_add = QPushButton("Install from folder…")
        b_add.clicked.connect(self._install)
        row.addWidget(b_add)
        b_open = QPushButton("Open add-ons folder")
        b_open.clicked.connect(self._open_folder)
        row.addWidget(b_open)
        b_refresh = QPushButton("Refresh")
        b_refresh.clicked.connect(self._refresh)
        row.addWidget(b_refresh)
        row.addStretch(1)
        v.addLayout(row)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["On", "Add-on", "Version", "Author", "Status"])
        self.tree.setRootIsDecorated(False)
        self.tree.setColumnWidth(0, 34)
        self.tree.setColumnWidth(1, 150)
        self.tree.itemChanged.connect(self._item_changed)
        v.addWidget(self.tree, 1)

        v.addWidget(QLabel("Logs"))
        self.logs = mono(QPlainTextEdit())
        self.logs.setReadOnly(True)
        self.logs.setMaximumHeight(120)
        v.addWidget(self.logs)
        b_logs = QPushButton("Refresh logs")
        b_logs.clicked.connect(self._refresh_logs)
        v.addWidget(b_logs)

        self._refresh()
        self._refresh_logs()

    # -------------------------------------------------- list
    def _refresh(self):
        self.tree.blockSignals(True)
        self.tree.clear()
        found = loader.discover(self.win.data_dir)
        rows = {r["meta"]["_id"]: r for r in getattr(self.win, "_addon_rows", [])}
        for meta in found:
            aid = meta["_id"]
            enabled = loader.is_enabled(self.win.settings, aid)
            row = rows.get(aid)
            status = "enabled" if enabled else "disabled"
            if row and enabled and not row.get("ok"):
                status = f"error: {row.get('error')}"
            elif enabled and row is None:
                status = "enabled (restart to load)"
            it = QTreeWidgetItem(["", meta.get("name", aid), str(meta.get("version", "")),
                                  str(meta.get("author", "")), status])
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(0, Qt.CheckState.Checked if enabled else Qt.CheckState.Unchecked)
            it.setData(0, Qt.ItemDataRole.UserRole, meta)
            it.setToolTip(1, meta.get("description", ""))
            self.tree.addTopLevelItem(it)
        if not found:
            self.tree.addTopLevelItem(QTreeWidgetItem(["", "No add-ons installed", "", "", "Install from folder…"]))
        self.tree.blockSignals(False)

    def _item_changed(self, it, col):
        if col != 0:
            return
        meta = it.data(0, Qt.ItemDataRole.UserRole)
        if not meta:
            return
        want = it.checkState(0) == Qt.CheckState.Checked
        aid = meta["_id"]
        if want and not loader.is_enabled(self.win.settings, aid):
            ok = security_warning(
                self, "caution", f"Enable “{meta.get('name', aid)}”?",
                f"Add-ons are <b>Python code that runs inside Wyrm</b> with full access, by <b>"
                f"{meta.get('author', 'unknown')}</b>. Only enable it if you trust the source.",
                ["It can read and modify the traffic flowing through the proxy",
                 "It runs with the same access as Wyrm itself"],
                proceed="Enable add-on", back="Cancel")
            if not ok:
                self.tree.blockSignals(True)
                it.setCheckState(0, Qt.CheckState.Unchecked)
                self.tree.blockSignals(False)
                return
        loader.set_enabled(self.win.settings, aid, want)
        self.win.toast(f"“{meta.get('name', aid)}” {'enabled' if want else 'disabled'} — restart Wyrm to apply.", 6000)
        self._refresh()

    # -------------------------------------------------- install / folder
    def _install(self):
        src = QFileDialog.getExistingDirectory(self, "Choose an add-on folder (containing manifest.json)")
        if not src:
            return
        srcp = Path(src)
        if not (srcp / "manifest.json").is_file():
            QMessageBox.warning(self, "Add-ons", "That folder has no manifest.json — it isn't a Wyrm add-on.")
            return
        root = loader.addons_root(self.win.data_dir)
        root.mkdir(parents=True, exist_ok=True)
        dest = root / srcp.name
        if dest.exists():
            if QMessageBox.question(self, "Add-ons", f"“{srcp.name}” is already installed. Replace it?") \
                    != QMessageBox.StandardButton.Yes:
                return
            shutil.rmtree(dest, ignore_errors=True)
        try:
            shutil.copytree(srcp, dest)
        except OSError as e:
            QMessageBox.warning(self, "Add-ons", f"Couldn't install the add-on:\n{e}")
            return
        self.win.toast(f"Installed “{srcp.name}”. Enable it in the list, then restart Wyrm.", 7000)
        self._refresh()

    def _open_folder(self):
        root = loader.addons_root(self.win.data_dir)
        root.mkdir(parents=True, exist_ok=True)
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(root)))

    def _refresh_logs(self):
        lines = []
        for ctx in getattr(self.win, "_addon_ctxs", []):
            for ln in getattr(ctx, "_logs", []):
                lines.append(f"[{ctx.name}] {ln}")
        self.logs.setPlainText("\n".join(lines[-200:]) or "No add-on logs yet.")
