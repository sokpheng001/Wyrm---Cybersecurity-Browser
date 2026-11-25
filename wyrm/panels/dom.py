#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/dom.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Security panel → DOM Analysis: passive DOM-XSS source/sink scan."""
from __future__ import annotations

import json
from html import escape
from urllib.parse import urlparse

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import QHBoxLayout, QHeaderView, QLabel, QPushButton, QSplitter, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from .common import PAGEINFO_JS, SEV_COLOR, sev_badge, sev_title
from ..security import domscan
from ..widgets import SkeletonOverlay


# =================================================================== DOM Security Analysis
class DomTab(QWidget):
    """Dedicated passive DOM source/sink analysis built on domscan.py (extends pageinfo.js data)."""

    def __init__(self, win):
        super().__init__()
        self.win = win
        self.url = ""
        v = QVBoxLayout(self)
        intro = QLabel("Passive <b>DOM Security Analysis</b>: scans the scripts this page already loads for DOM-XSS "
                       "<b>sources</b> (attacker-influenceable inputs) and <b>sinks</b> (APIs that turn strings into "
                       "markup/code), and flags scripts containing both as potential flows. Read-only — it never "
                       "executes payloads or modifies the page.")
        intro.setWordWrap(True)
        intro.setObjectName("Muted")
        v.addWidget(intro)
        row = QHBoxLayout()
        self.btn = QPushButton("Analyze current page")
        self.btn.setObjectName("Primary")
        self.btn.clicked.connect(self.analyze_current)
        row.addWidget(self.btn)
        self.counts = QLabel("")
        self.counts.setObjectName("Muted")
        row.addWidget(self.counts)
        row.addStretch(1)
        v.addLayout(row)
        split = QSplitter(Qt.Orientation.Vertical)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Finding", "Severity"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.currentItemChanged.connect(self._show)
        split.addWidget(self.tree)
        self.busy = SkeletonOverlay(self.tree)
        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        split.addWidget(self.detail)
        split.setSizes([360, 200])
        v.addWidget(split, 1)
        br = QHBoxLayout()
        self.b_add = QPushButton("Add to findings")
        self.b_add.clicked.connect(self._add)
        self.b_copy = QPushButton("Copy")
        self.b_copy.clicked.connect(self._copy)
        br.addWidget(self.b_add)
        br.addWidget(self.b_copy)
        br.addStretch(1)
        v.addLayout(br)
        self._show()

    def analyze_current(self):
        view = self.win.current_view()
        if not view:
            return
        url = view.url().toString()
        if not url.startswith("http"):
            self.counts.setText("Open an http(s) page to analyze it.")
            return
        self.url = url
        self.btn.setEnabled(False)
        self.busy.start("Scanning DOM scripts…")
        view.page().runJavaScript(PAGEINFO_JS, 0, lambda res, u=url: self._got_page(u, res))

    def _got_page(self, url, res):
        try:
            page = json.loads(res) if isinstance(res, str) else (res or {})
        except ValueError:
            page = {}
        page.setdefault("url", url)
        eng = self.win.engagement
        in_scope = (lambda h: bool(eng.in_scope(h))) if eng and eng.scope else \
            (lambda h, base=urlparse(url).hostname: h == base)
        px, verify = self.win.proxies(), self.win.verify_tls()
        self.win.runner.run(lambda: domscan.analyze_dom(page, in_scope, px, verify),
                            lambda ok, r, u=url: self._done(u, ok, r))

    def _done(self, url, ok, r):
        self.btn.setEnabled(True)
        self.busy.stop()
        if url != self.url:
            return
        if not ok:
            self.counts.setText(f"DOM analysis failed: {r}")
            return
        c = r["counts"]
        from urllib.parse import urlparse
        pu = urlparse(url)
        loc = ((pu.netloc + pu.path) or url)[:60]   # QA-L1: show which URL these results are for
        self.counts.setText(f"{loc} · {c['sinks']} sinks · {c['sources']} sources · {c['flows']} potential flows "
                            f"· {c['scripts']} script(s) scanned")
        self.tree.clear()
        groups: dict[str, QTreeWidgetItem] = {}
        order = ["DOM potential flow", "DOM sinks", "DOM sources"]
        for i in sorted(r["issues"], key=lambda i: order.index(i["category"]) if i["category"] in order else 9):
            g = groups.get(i["category"])
            if not g:
                g = QTreeWidgetItem([i["category"], ""])
                fnt = g.font(0)
                fnt.setBold(True)
                g.setFont(0, fnt)
                self.tree.addTopLevelItem(g)
                groups[i["category"]] = g
            it = QTreeWidgetItem([i["title"], sev_title(i["severity"])])
            it.setForeground(1, QBrush(QColor(SEV_COLOR.get(i["severity"], "#888"))))
            it.setData(0, Qt.ItemDataRole.UserRole, i)
            g.addChild(it)
        for cat, g in groups.items():
            g.setText(0, f"{cat}  ({g.childCount()})")
            g.setExpanded(cat != "DOM sources")
        if not r["issues"]:
            self.tree.addTopLevelItem(QTreeWidgetItem(["No DOM sources or sinks found in the scanned scripts.", ""]))

    def _issue(self):
        it = self.tree.currentItem()
        return it.data(0, Qt.ItemDataRole.UserRole) if it else None

    def _show(self, *_):
        i = self._issue()
        self.b_add.setEnabled(bool(i) and bool(self.win.engagement))
        self.b_copy.setEnabled(bool(i))
        if not i:
            self.detail.setHtml("<p style='color:gray'>Select a finding for details. Heuristic static analysis — "
                                "a 'potential flow' means a script contains both a source and a sink; confirm the "
                                "data actually flows from source to sink before reporting.</p>")
            return
        html = f"<p>{sev_badge(i['severity'])} <b>{escape(i['title'])}</b></p>"
        if i.get("detail"):
            html += f"<p>{escape(i['detail'])}</p>"
        if i.get("evidence"):
            html += f"<pre style='white-space:pre-wrap'>{escape(i['evidence'])}</pre>"
        self.detail.setHtml(html)

    def _copy(self):
        i = self._issue()
        if i:
            QGuiApplication.clipboard().setText(f"[{i['severity'].upper()}] {i['title']}\n{i.get('detail','')}\n"
                                                f"{i.get('evidence','')}".strip())

    def _add(self):
        i = self._issue()
        if i:
            sev = i["severity"] if i["severity"] != "info" else "low"
            self.win.add_finding_dialog(title=i["title"], severity=sev, url=self.url,
                                        description=i.get("detail", ""), evidence=i.get("evidence", ""))
