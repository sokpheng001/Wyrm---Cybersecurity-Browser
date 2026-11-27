#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/tabsearch.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Quick tab switcher (Ctrl+Shift+A, like Chrome): a popup that searches every open tab — in this window and in
the other windows that share its profile — by title or address, and jumps to the one you pick."""
from __future__ import annotations

from PySide6.QtCore import QEvent, Qt
from PySide6.QtWidgets import (QApplication, QLineEdit, QListWidget, QListWidgetItem, QVBoxLayout, QWidget)


class TabSearchPopup(QWidget):
    def __init__(self, win):
        # a Popup closes itself on an outside click or Esc and never floats across tabs
        super().__init__(win, Qt.WindowType.Popup | Qt.WindowType.FramelessWindowHint)
        self.win = win
        self.setObjectName("TabSearchPopup")
        self.setFixedWidth(420)
        v = QVBoxLayout(self)
        v.setContentsMargins(10, 10, 10, 10)
        v.setSpacing(8)
        self.search = QLineEdit(objectName="TabSearchInput")
        self.search.setPlaceholderText("Search open tabs…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._filter)
        self.search.installEventFilter(self)
        v.addWidget(self.search)
        self.list = QListWidget(objectName="TabSearchList")
        self.list.setUniformItemSizes(True)
        self.list.itemActivated.connect(lambda it: self._choose(it))
        self.list.itemClicked.connect(lambda it: self._choose(it))
        v.addWidget(self.list)
        self._entries: list[dict] = []

    # ---- data: every tab across this window's same-profile windows
    def _collect(self) -> list[dict]:
        wins = [self.win] + [w for w in QApplication.instance().topLevelWidgets()
                             if w is not self.win and isinstance(w, type(self.win)) and not w.isHidden()
                             and getattr(w, "profile", None) is getattr(self.win, "profile", None)]
        out = []
        for w in wins:
            for i in range(w.tabbar.count()):
                view = w.tabbar.tabData(i)
                if view is None:
                    continue
                title = w.tabbar.tabText(i) or view.title() or "New tab"
                url = view.url().toString()
                out.append({"win": w, "view": view, "title": title, "url": url,
                            "current": (w is self.win and i == w.tabbar.currentIndex())})
        return out

    def popup(self):
        self._entries = self._collect()
        self.search.clear()
        self._filter("")
        # center near the top of the window
        g = self.win.geometry()
        self.move(g.x() + (g.width() - self.width()) // 2, g.y() + 90)
        self.show()
        self.search.setFocus()

    def _filter(self, text):
        q = (text or "").lower().strip()
        self.list.clear()
        for e in self._entries:
            hay = (e["title"] + " " + e["url"]).lower()
            if q and not all(w in hay for w in q.split()):
                continue
            label = e["title"]
            if e["url"] and not e["url"].startswith("wyrm:"):
                label += "   —   " + e["url"][:70]
            it = QListWidgetItem(("● " if e["current"] else "   ") + label)
            it.setData(Qt.ItemDataRole.UserRole, e)
            self.list.addItem(it)
        if self.list.count():
            self.list.setCurrentRow(0)

    def _choose(self, it):
        e = it.data(Qt.ItemDataRole.UserRole) if it else None
        self.close()
        if not e:
            return
        w, view = e["win"], e["view"]
        idx = next((i for i in range(w.tabbar.count()) if w.tabbar.tabData(i) is view), -1)
        if idx >= 0:
            w.tabbar.setCurrentIndex(idx)
            if w.isHidden():
                w.showNormal()
            w.raise_()
            w.activateWindow()

    def eventFilter(self, obj, ev):
        if obj is self.search and ev.type() == QEvent.Type.KeyPress:
            k = ev.key()
            if k in (Qt.Key.Key_Down, Qt.Key.Key_Up):   # arrow keys move the selection in the list
                row = self.list.currentRow()
                self.list.setCurrentRow(max(0, min(self.list.count() - 1,
                                                   row + (1 if k == Qt.Key.Key_Down else -1))))
                return True
            if k in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
                if self.list.currentItem():
                    self._choose(self.list.currentItem())
                return True
        return super().eventFilter(obj, ev)
