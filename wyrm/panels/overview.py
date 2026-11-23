#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/overview.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Security panel → Overview: passive security grade of the current page."""
from __future__ import annotations

import json
from html import escape
from urllib.parse import urlparse

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QHeaderView, QLabel, QPushButton, QSplitter, QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from .common import PAGEINFO_JS, SEV_COLOR, sev_badge
from .. import theme
from ..security import analyzer, intel
from ..widgets import BusyOverlay


# =================================================================== Overview
class OverviewTab(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.result = None
        self.url = ""
        v = QVBoxLayout(self)
        head = QHBoxLayout()
        self.grade = QLabel("–")
        self.grade.setFixedSize(56, 56)
        self.grade.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._paint_grade("–")
        head.addWidget(self.grade)
        col = QVBoxLayout()
        self.target = QLabel("Open a page and press Analyze")
        self.target.setWordWrap(True)
        self.target.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.summary = QLabel("")
        self.summary.setObjectName("Muted")
        col.addWidget(self.target)
        col.addWidget(self.summary)
        head.addLayout(col, 1)
        v.addLayout(head)
        row = QHBoxLayout()
        self.btn = QPushButton("Analyze this page")
        self.btn.setObjectName("Primary")
        self.btn.clicked.connect(self.analyze_current)
        row.addWidget(self.btn)
        self.auto = QCheckBox("Auto-analyze in-scope pages")
        self.auto.setChecked(win.settings.value("sec/auto", True, type=bool))
        self.auto.toggled.connect(lambda b: win.settings.setValue("sec/auto", b))
        row.addWidget(self.auto)
        row.addStretch(1)
        v.addLayout(row)

        split = QSplitter(Qt.Orientation.Vertical)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Issue", "Severity"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.currentItemChanged.connect(self._show_detail)
        self.tree.itemDoubleClicked.connect(self._open_item)
        split.addWidget(self.tree)
        self.busy = BusyOverlay(self.tree)
        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        self.detail.anchorClicked.connect(lambda u: win.open_url(u.toString(), new_tab=True))
        split.addWidget(self.detail)
        split.setSizes([360, 200])
        v.addWidget(split, 1)
        btns = QHBoxLayout()
        self.b_add = QPushButton("Add to findings")
        self.b_add.clicked.connect(self._add_finding)
        self.b_cve = QPushButton("Look up CVEs")
        self.b_cve.clicked.connect(self._lookup_cves)
        self.b_copy = QPushButton("Copy")
        self.b_copy.clicked.connect(self._copy)
        for b in (self.b_add, self.b_cve, self.b_copy):
            btns.addWidget(b)
        v.addLayout(btns)
        self._show_detail(None)

    def _paint_grade(self, g):
        color = theme.GRADE.get(g, "#8d8d8d")
        fg = "#161616" if g == "C" else "#ffffff"
        self.grade.setText(g)
        self.grade.setStyleSheet(f"background:{color};color:{fg};border-radius:0;font-size:28px;font-weight:300")

    def page_loaded(self, view):
        url = view.url().toString()
        if not url.startswith("http"):
            return
        host = urlparse(url).hostname or ""
        if self.auto.isChecked() and self.win.engagement and self.win.engagement.in_scope(host):
            self.analyze_current()

    def analyze_current(self):
        view = self.win.current_view()
        if not view:
            return
        url = view.url().toString()
        if not url.startswith("http"):
            self.target.setText("Open an http(s) page to analyze it.")
            return
        self.url = url
        self.target.setText(f"<b>{escape(urlparse(url).hostname or url)}</b><br><span style='color:gray'>"
                            f"{escape(url[:120])}</span>")
        self.summary.setText("Collecting page data…")
        self.btn.setEnabled(False)
        self._paint_grade("…")
        self.busy.start("Analyzing page…")
        view.page().runJavaScript(PAGEINFO_JS, 0, lambda res, u=url: self._got_page(u, res))

    def _got_page(self, url, res):
        try:
            page = json.loads(res) if isinstance(res, str) else (res or {})
        except ValueError:
            page = {}
        page.setdefault("url", url)
        page.setdefault("https", url.startswith("https"))
        self.summary.setText("Checking headers, cookies, TLS, technologies, JavaScript…")
        eng = self.win.engagement
        in_scope = (lambda h: bool(eng.in_scope(h))) if eng and eng.scope else \
            (lambda h, base=urlparse(url).hostname: h == base)  # personal mode: same host only
        px, verify = self.win.proxies(), self.win.verify_tls()
        self.win.runner.run(lambda: analyzer.analyze(url, page, in_scope, px, verify),
                            lambda ok, r, u=url: self._done(u, ok, r))

    def _done(self, url, ok, r):
        self.btn.setEnabled(True)
        self.busy.stop()
        if url != self.url:
            return
        if not ok:
            self._paint_grade("?")
            self.summary.setText(f"Analysis failed: {r}")
            return
        self.result = r
        self._paint_grade(r["grade"])
        counts = {}
        for i in r["issues"]:
            counts[i["severity"]] = counts.get(i["severity"], 0) + 1
        parts = [f"<span style='color:{SEV_COLOR[s]}'>{counts[s]} {s}</span>"
                 for s in ("critical", "high", "medium", "low", "info") if counts.get(s)]
        status = f"HTTP {r.get('status')} · " if r.get("status") else ""
        self.summary.setText(status + " · ".join(parts) + ("  ⚠ " + "; ".join(r["errors"]) if r["errors"] else ""))
        self.tree.clear()
        groups: dict[str, QTreeWidgetItem] = {}
        order = ["Content-Security-Policy", "Security headers", "Cookies", "TLS", "Page", "CORS",
                 "JavaScript: possible secrets", "Information disclosure", "Technologies", "JavaScript: endpoints"]
        for i in sorted(r["issues"], key=lambda i: order.index(i["category"]) if i["category"] in order else 99):
            g = groups.get(i["category"])
            if not g:
                g = QTreeWidgetItem([i["category"], ""])
                f = g.font(0)
                f.setBold(True)
                g.setFont(0, f)
                self.tree.addTopLevelItem(g)
                groups[i["category"]] = g
            it = QTreeWidgetItem([i["title"], i["severity"]])
            it.setForeground(1, QBrush(QColor(SEV_COLOR.get(i["severity"], "#888"))))
            it.setData(0, Qt.ItemDataRole.UserRole, i)
            g.addChild(it)
        for cat, g in groups.items():
            worst = min((g.child(k).text(1) for k in range(g.childCount())),
                        key=lambda s: analyzer.SEV_ORDER.get(s, 9))
            g.setText(0, f"{cat}  ({g.childCount()})")
            g.setText(1, worst)
            g.setForeground(1, QBrush(QColor(SEV_COLOR.get(worst, "#888"))))
            g.setExpanded(analyzer.SEV_ORDER.get(worst, 9) <= 2 and g.childCount() < 25)

    def _issue(self) -> dict | None:
        it = self.tree.currentItem()
        return it.data(0, Qt.ItemDataRole.UserRole) if it else None

    def _show_detail(self, *_):
        i = self._issue()
        self.b_add.setEnabled(bool(i) and bool(self.win.engagement))
        self.b_add.setToolTip("" if self.win.engagement else "Select an engagement to record findings")
        self.b_cve.setEnabled(bool(i and i.get("tech") and i["tech"].get("version")))
        self.b_copy.setEnabled(bool(i))
        if not i:
            self.detail.setHtml("<p style='color:gray'>Passive checks only: one normal request for headers, a TLS "
                                "handshake, and the scripts the page already loads. Select an issue for details.</p>")
            return
        html = f"<p>{sev_badge(i['severity'])} <b>{escape(i['title'])}</b></p>"
        if i.get("detail"):
            html += f"<p>{escape(i['detail'])}</p>"
        if i.get("evidence"):
            html += f"<pre style='white-space:pre-wrap'>{escape(i['evidence'])}</pre>"
        if i.get("url"):
            html += f"<p><a href='{escape(i['url'], quote=True)}'>Open {escape(i['url'][:80])}</a> (double-click)</p>"
        if i.get("cves") is not None:
            if not i["cves"]:
                html += "<p>No known vulnerabilities found for this exact version.</p>"
            for c in i["cves"][:25]:
                sc = f" · CVSS {c['score']}" if c.get("score") else ""
                html += (f"<p>{sev_badge(c.get('severity') or 'info')} <a href='{c['url']}'>{escape(c['id'])}</a>{sc}"
                         f"<br><span style='color:gray'>{escape(c['summary'][:240])}</span></p>")
        self.detail.setHtml(html)

    def _open_item(self, item, _col):
        i = item.data(0, Qt.ItemDataRole.UserRole)
        if i and i.get("url"):
            self.win.open_url(i["url"], new_tab=True)

    def _copy(self):
        i = self._issue()
        if i:
            QGuiApplication.clipboard().setText(f"[{i['severity'].upper()}] {i['title']}\n{i.get('detail', '')}\n{i.get('evidence', '')}".strip())

    def _add_finding(self):
        i = self._issue()
        if i:
            sev = i["severity"] if i["severity"] != "info" else "low"
            self.win.add_finding_dialog(title=i["title"], severity=sev, url=self.url,
                                        description=i.get("detail", ""), evidence=i.get("evidence", ""))

    def _lookup_cves(self):
        it = self.tree.currentItem()
        i = self._issue()
        if not i or not i.get("tech"):
            return
        self.b_cve.setEnabled(False)
        self.detail.setHtml(f"<p>Looking up known vulnerabilities for <b>{escape(i['title'])}</b>…</p>")

        def done(ok, res):
            self.b_cve.setEnabled(True)
            if not ok:
                self.detail.setHtml(f"<p style='color:#ea4335'>CVE lookup failed: {escape(str(res))}</p>")
                return
            i["cves"] = res
            if res:
                worst = "high" if any((c.get("severity") or "") in ("high", "critical") for c in res) else "medium"
                i["severity"] = worst
                i["detail"] = f"{len(res)} known vulnerabilit{'y' if len(res) == 1 else 'ies'} affect this version."
                it.setText(1, worst)
                it.setForeground(1, QBrush(QColor(SEV_COLOR[worst])))
                it.setText(0, f"{i['title']}  ({len(res)} CVEs)")
            it.setData(0, Qt.ItemDataRole.UserRole, i)
            self._show_detail()
        self.win.runner.run(intel.lookup_cves, done, i["tech"])
