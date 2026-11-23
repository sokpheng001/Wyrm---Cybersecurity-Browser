#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/traffic.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Security panel → Traffic: every request, filterable, with per-site focus."""
from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QTimer, Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import QAbstractItemView, QCheckBox, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QPushButton, QTableView, QVBoxLayout, QWidget

from .common import mono
from ..linkguard import registered_domain
from ..security import tools


# =================================================================== Traffic
class TrafficModel(QAbstractTableModel):
    COLS = ["Time", "Method", "Type", "Host", "Path", "Scope"]
    MAX = 5000

    def __init__(self):
        super().__init__()
        self.rows: list[dict] = []

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.rows)

    def columnCount(self, parent=QModelIndex()):
        return len(self.COLS)

    def headerData(self, s, o, role=Qt.ItemDataRole.DisplayRole):
        if o == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            return self.COLS[s]

    def data(self, idx, role=Qt.ItemDataRole.DisplayRole):
        r = self.rows[idx.row()]
        c = idx.column()
        if role == Qt.ItemDataRole.DisplayRole:
            scope = {True: "in", False: "OUT", None: "–"}[r["in_scope"]] + (" ⛔" if r["blocked"] else "")
            return [r["time"], r["method"], r["type"], r["host"], r["path"], scope][c]
        if role == Qt.ItemDataRole.ForegroundRole:
            if r["blocked"]:
                return QBrush(QColor("#ea4335"))
            if c == 5 and r["in_scope"] is True:
                return QBrush(QColor("#1e8e3e"))
            if c == 5 and r["in_scope"] is False:
                return QBrush(QColor("#fa7b17"))
        if role == Qt.ItemDataRole.ToolTipRole:
            return r["url"]
        if role == Qt.ItemDataRole.UserRole:
            return r

    def add(self, entry):
        if len(self.rows) >= self.MAX:
            self.beginRemoveRows(QModelIndex(), 0, 499)
            del self.rows[:500]
            self.endRemoveRows()
        n = len(self.rows)
        self.beginInsertRows(QModelIndex(), n, n)
        self.rows.append(entry)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self.rows.clear()
        self.endResetModel()


class TrafficFilter(QSortFilterProxyModel):
    STATIC = {"Image", "FontResource", "Stylesheet", "Media", "Favicon"}

    def __init__(self):
        super().__init__()
        self.text = ""
        self.in_scope_only = False
        self.hide_static = True
        self.focus_domain = ""   # when set, show only this registered domain (the target under test)

    def filterAcceptsRow(self, row, parent):
        r = self.sourceModel().rows[row]
        if self.focus_domain and registered_domain(r["host"]) != self.focus_domain:
            return False
        if self.in_scope_only and r["in_scope"] is not True:
            return False
        if self.hide_static and r["type"] in self.STATIC:
            return False
        return not self.text or self.text in r["url"].lower() or self.text in r["method"].lower()


class TrafficTab(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.model = TrafficModel()
        self.proxy = TrafficFilter()
        self.proxy.setSourceModel(self.model)
        v = QVBoxLayout(self)
        # site focus: look at one target's traffic, or all
        site_row = QHBoxLayout()
        site_row.addWidget(QLabel("Site"))
        self.site_box = QComboBox()
        self.site_box.addItem("All traffic", "")
        self.site_box.currentIndexChanged.connect(self._refilter)
        site_row.addWidget(self.site_box, 1)
        self.b_focus = QPushButton("Focus current site")
        self.b_focus.clicked.connect(self.focus_current)
        site_row.addWidget(self.b_focus)
        v.addLayout(site_row)
        self._domains: set[str] = set()

        row = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter URL / method…")
        self.filter.textChanged.connect(self._refilter)
        row.addWidget(self.filter, 1)
        self.c_scope = QCheckBox("In-scope only")
        self.c_scope.toggled.connect(self._refilter)
        self.c_static = QCheckBox("Hide static")
        self.c_static.setChecked(True)
        self.c_static.toggled.connect(self._refilter)
        row.addWidget(self.c_scope)
        row.addWidget(self.c_static)
        b_int = QPushButton("Intercept…")
        b_int.setToolTip("Hold page requests to edit, forward or drop them (Burp-style), Ctrl+Alt+I")
        b_int.clicked.connect(lambda: self.win.open_intercept())
        row.addWidget(b_int)
        clear = QPushButton("Clear")
        clear.clicked.connect(self.clear)
        row.addWidget(clear)
        v.addLayout(row)
        self.table = mono(QTableView())
        self.table.setModel(self.proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        h = self.table.horizontalHeader()
        for c, mode in enumerate([QHeaderView.ResizeMode.ResizeToContents] * 4 + [QHeaderView.ResizeMode.Stretch,
                                                                                  QHeaderView.ResizeMode.ResizeToContents]):
            h.setSectionResizeMode(c, mode)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.table.doubleClicked.connect(lambda idx: self._send_to_repeater(self._row(idx)))
        v.addWidget(self.table, 1)
        self.count = QLabel("")
        self.count.setObjectName("Muted")
        v.addWidget(self.count)
        self._follow = True
        self.model.rowsInserted.connect(self._on_insert)

    def _refilter(self):
        self.proxy.text = self.filter.text().lower().strip()
        self.proxy.in_scope_only = self.c_scope.isChecked()
        self.proxy.hide_static = self.c_static.isChecked()
        self.proxy.focus_domain = self.site_box.currentData() or ""
        self.proxy.invalidateFilter()
        self._update_count()

    def focus_current(self):
        v = self.win.current_view() if hasattr(self.win, "tabbar") else None
        host = v.url().host() if v and v.url().scheme().startswith("http") else ""
        if not host:
            self.win.toast("Open the site you're testing first, then focus it")
            return
        dom = registered_domain(host)
        self._ensure_domain(dom)
        self.site_box.setCurrentIndex(max(0, self.site_box.findData(dom)))

    def _ensure_domain(self, dom: str):
        if dom and dom not in self._domains:
            self._domains.add(dom)
            for d in sorted(self._domains):  # rebuild so the list stays sorted
                if self.site_box.findData(d) < 0:
                    self.site_box.addItem(d, d)

    def _on_insert(self, first, *_):
        for r in self.model.rows[-50:]:  # pick up new domains for the selector
            self._ensure_domain(registered_domain(r["host"]))
        sb = self.table.verticalScrollBar()
        at_bottom = sb.value() >= sb.maximum() - 30
        self._update_count()
        if at_bottom:
            QTimer.singleShot(0, self.table.scrollToBottom)

    def _update_count(self):
        rows = self.model.rows
        blocked = sum(1 for r in rows if r["blocked"])
        focus = self.proxy.focus_domain
        shown = self.proxy.rowCount()
        label = f"{shown} shown" + (f" · focused on {focus}" if focus else "")
        self.count.setText(f"{label} · {len(rows)} total · {blocked} blocked")

    def clear(self):
        self.model.clear()
        self._domains.clear()
        self.site_box.blockSignals(True)
        self.site_box.clear()
        self.site_box.addItem("All traffic", "")
        self.site_box.blockSignals(False)
        self._update_count()

    def add(self, entry):
        self.model.add(entry)

    def _row(self, idx) -> dict:
        return self.proxy.data(idx, Qt.ItemDataRole.UserRole)

    def _menu(self, pos):
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        r = self._row(idx)
        m = QMenu(self)
        m.addAction("Send to Repeater", lambda: self._send_to_repeater(r))
        m.addAction("Send to Intruder", lambda: self._send_to_intruder(r))
        m.addAction("Send to Comparer", lambda: self._send_to_comparer(r))
        m.addAction("Open in new tab", lambda: self.win.open_url(r["url"], new_tab=True))
        m.addSeparator()
        m.addAction("Copy URL", lambda: QGuiApplication.clipboard().setText(r["url"]))
        m.addAction("Copy as cURL", lambda: QGuiApplication.clipboard().setText(
            tools.to_curl(r["method"], r["url"], r.get("headers"))))
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _send_to_comparer(self, r):
        hdrs = "".join(f"{k}: {v}\n" for k, v in (r.get("headers") or {}).items())
        text = f"{r['method']} {r['url']}\n" + hdrs
        self.win.security.tools_tab.compare_add(text)
        self.win.security.show_tab("Tools")

    def _send_to_intruder(self, r):
        self.win.security.intruder.load_request(r["method"], r["url"], r.get("headers") or {})
        self.win.security.show_tab("Intruder")

    def _send_to_repeater(self, r):
        self.win.security.tools_tab.load_request(r["method"], r["url"], r.get("headers") or {})
        self.win.security.show_tab("Tools")
