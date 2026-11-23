#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/findings.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Security panel → Findings: engagement findings and report export."""
from __future__ import annotations

from datetime import datetime
from html import escape
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import QFileDialog, QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from .common import SEV_COLOR
from ..dialogs import FindingDialog
from ..security import report


# =================================================================== Findings
class FindingsTab(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        v = QVBoxLayout(self)
        self.header = QLabel("")
        self.header.setWordWrap(True)
        v.addWidget(self.header)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Severity", "Finding", "URL"])
        self.tree.setRootIsDecorated(False)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.tree.itemDoubleClicked.connect(lambda *_: self._edit())
        v.addWidget(self.tree, 1)
        row = QHBoxLayout()
        self.b_add = QPushButton("Add finding")
        self.b_add.setObjectName("Primary")
        self.b_add.clicked.connect(lambda: self.win.add_finding_dialog())
        self.b_edit = QPushButton("Edit")
        self.b_edit.clicked.connect(self._edit)
        self.b_del = QPushButton("Delete")
        self.b_del.clicked.connect(self._delete)
        self.b_export = QPushButton("Export report…")
        self.b_export.clicked.connect(self._export)
        for b in (self.b_add, self.b_edit, self.b_del, self.b_export):
            row.addWidget(b)
        v.addLayout(row)
        self.refresh()

    def refresh(self):
        eng = self.win.engagement
        self.tree.clear()
        for b in (self.b_add, self.b_edit, self.b_del, self.b_export):
            b.setEnabled(bool(eng))
        if not eng:
            self.header.setText("<span style='color:gray'>Select or create an engagement (toolbar) to record "
                                "findings and export a report.</span>")
            return
        rows = self.win.store.findings(eng.id)
        counts = self.win.store.counts(eng.id)
        chips = " ".join(f"<span style='color:{SEV_COLOR[s]}'>{counts[s]} {s}</span>"
                         for s in ("critical", "high", "medium", "low", "info") if counts.get(s))
        self.header.setText(f"<b>{escape(eng.name)}</b> · {len(rows)} findings {('· ' + chips) if chips else ''}")
        for f in rows:
            it = QTreeWidgetItem([f["severity"].upper(), f["title"], f["url"] or ""])
            it.setForeground(0, QBrush(QColor(SEV_COLOR.get(f["severity"], "#888"))))
            it.setData(0, Qt.ItemDataRole.UserRole, f["id"])
            if f.get("screenshot"):
                it.setToolTip(1, "Has screenshot")
            self.tree.addTopLevelItem(it)

    def _selected(self):
        it = self.tree.currentItem()
        if not it:
            return None
        fid = it.data(0, Qt.ItemDataRole.UserRole)
        return next((f for f in self.win.store.findings(self.win.engagement.id) if f["id"] == fid), None)

    def _edit(self):
        f = self._selected()
        if not f:
            return
        d = FindingDialog(self, f["title"], f["severity"], f["url"], f["description"], f["evidence"], edit=True)
        if d.exec():
            self.win.store.update_finding(f["id"], **d.values())
            self.refresh()

    def _delete(self):
        f = self._selected()
        if f and QMessageBox.question(self, "Delete finding", f"Delete '{f['title']}'?") == QMessageBox.StandardButton.Yes:
            self.win.store.delete_finding(f["id"])
            self.refresh()

    def _export(self):
        eng = self.win.engagement
        rows = self.win.store.findings(eng.id)
        safe = "".join(c if c.isalnum() else "_" for c in eng.name)
        path, flt = QFileDialog.getSaveFileName(self, "Export report", f"{safe}_report_{datetime.now():%Y%m%d}.html",
                                                "HTML report (*.html);;Markdown (*.md)")
        if not path:
            return
        text = report.to_markdown(eng, rows) if path.lower().endswith(".md") else report.to_html(eng, rows)
        Path(path).write_text(text, encoding="utf-8")
        self.win.open_url(Path(path).as_uri(), new_tab=True) if path.lower().endswith(".html") else None
        self.win.toast(f"Report saved: {path}")
