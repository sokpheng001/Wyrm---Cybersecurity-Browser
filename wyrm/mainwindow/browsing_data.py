#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/browsing_data.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Developer: @kwan (history page and Clear browsing data)
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""History page and "Clear browsing data" (history, cookies, cached files)."""
from __future__ import annotations

import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from .. import pages


class BrowsingDataMixin:
    """History page + Clear browsing data dialog. (Mixed into MainWindow.)"""

    HISTORY_KEYS = ["Ctrl+Y"] if sys.platform == "darwin" else ["Ctrl+H"]  # ⌘Y like Safari; Ctrl+H elsewhere

    def open_history(self):
        self.open_url("wyrm://history", new_tab=True)

    def _history_page(self, query: str = "") -> str:
        if self.history_db is None:
            return pages.render_history([], query, private=True)
        return pages.render_history(self.history_db.entries(query, limit=1000), query, private=False)

    def clear_browsing_data(self):
        """Choose what to clear: browsing history, address-bar history, cookies, cached images and files."""
        d = QDialog(self, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        d.setObjectName("ClearDataDialog")
        v = QVBoxLayout(d)
        v.setContentsMargins(24, 20, 24, 18)
        v.setSpacing(10)
        title = QLabel("<b style='font-size:15px'>Clear browsing data</b>")
        v.addWidget(title)
        boxes = {
            "history": QCheckBox("Browsing history (the History page)"),
            "typed": QCheckBox("Search && address-bar history"),  # && = literal &
            "cookies": QCheckBox("Cookies (signs you out of most websites)"),
            "cache": QCheckBox("Cached images and files"),
        }
        for key, cb in boxes.items():
            cb.setChecked(key != "cookies")  # cookies off by default: clearing them signs you out
            v.addWidget(cb)
        if self.ephemeral:
            note = QLabel("This is a private/Tor window: its data is deleted anyway when you close it.")
            note.setObjectName("Muted")
            note.setWordWrap(True)
            v.addWidget(note)
        row = QHBoxLayout()
        row.addStretch(1)
        cancel, ok = QPushButton("Cancel"), QPushButton("Clear data")
        ok.setObjectName("Primary")
        ok.setDefault(True)
        cancel.clicked.connect(d.reject)
        ok.clicked.connect(d.accept)
        row.addWidget(cancel)
        row.addWidget(ok)
        v.addLayout(row)
        if d.exec() != QDialog.DialogCode.Accepted:
            return
        done = []
        if boxes["history"].isChecked() and self.history_db is not None:
            self.history_db.clear()
            done.append("browsing history")
        if boxes["typed"].isChecked():
            self.clear_history()
            done.append("address-bar history")
        for prof in list(self.profiles.values()):
            if boxes["cookies"].isChecked():
                prof.cookieStore().deleteAllCookies()
            if boxes["cache"].isChecked():
                prof.clearHttpCache()
            if boxes["history"].isChecked():
                prof.clearAllVisitedLinks()
        if boxes["cookies"].isChecked():
            done.append("cookies")
        if boxes["cache"].isChecked():
            done.append("cached files")
        self.toast("Cleared: " + ", ".join(done) if done else "Nothing was selected")
        self._refresh_home_pages()
        for i in range(self.tabbar.count()):  # an open History page shows the result right away
            view = self.tabbar.tabData(i)
            if view.url().scheme() == "wyrm" and view.url().host() == "history":
                view.reload()
