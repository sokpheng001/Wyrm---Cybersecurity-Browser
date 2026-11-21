#------------------------------------------------------------------------------
# Wyrm — wyrm/security_panel.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Security panel: Overview (passive checks) · Traffic · Recon · Tools · Findings."""
from __future__ import annotations

import json
import re
from datetime import datetime
from html import escape
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDockWidget, QDoubleSpinBox, QFileDialog, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
    QScrollArea, QSpinBox, QSplitter, QStackedWidget, QTabBar, QTableView, QTabWidget, QTextBrowser, QToolButton,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from . import theme
from .dialogs import FindingDialog
from .linkguard import registered_domain
from .widgets import BusyOverlay
from .security import analyzer, domscan, fuzzer, intel, report, tools

SEV_COLOR = theme.SEVERITY
PAGEINFO_JS = (Path(__file__).parent / "security" / "pageinfo.js").read_text(encoding="utf-8")


def mono(widget):
    f = widget.font()
    f.setFamilies([theme.MONO, "Consolas", "monospace"])
    widget.setFont(f)
    return widget


class HeaderHighlighter:
    """Colors 'Header-Name:' vs value in an editable request-headers box (keeps it editable)."""

    def __new__(cls, editor):
        from PySide6.QtCore import QRegularExpression
        from PySide6.QtGui import QColor, QSyntaxHighlighter, QTextCharFormat

        class _HL(QSyntaxHighlighter):
            def __init__(self, doc):
                super().__init__(doc)
                self.name_fmt = QTextCharFormat()
                self.name_fmt.setForeground(QColor("#8d8d8d"))
                self.name_fmt.setFontWeight(600)
                self.re = QRegularExpression(r"^([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s*:")

            def highlightBlock(self, text):
                m = self.re.match(text)
                if m.hasMatch():
                    self.setFormat(0, m.capturedEnd(1), self.name_fmt)
        return _HL(editor.document())


# syntax-highlight colors (readable on both light and dark response backgrounds)
_HL = {"key": "#0f62fe", "str": "#24a148", "num": "#ff832b", "kw": "#8a3ffc", "pun": "#8d8d8d",
       "tag": "#0f62fe", "com": "#8d8d8d", "hdr": "#8a3ffc"}
_JSON_TOK = re.compile(r'"(?:\\.|[^"\\])*"|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\],:]|\s+|[^"{}\[\],:\s]+')
_MARKUP_TOK = re.compile(r'<!--.*?-->|</?[^>]+>', re.S)
_GEN_TOK = re.compile(
    r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|(\b\d+(?:\.\d+)?\b)'
    r'|(\b(?:function|return|var|let|const|if|else|for|while|true|false|null|undefined|new|class|import|export|async|await)\b)')


def _span(color: str, text: str) -> str:
    return f"<span style='color:{color}'>{escape(text)}</span>"


def _hl_json(text: str) -> str:
    out = []
    for m in _JSON_TOK.finditer(text):
        t = m.group(0)
        if t.isspace():
            out.append(escape(t))
        elif t[0] == '"':
            out.append(_span(_HL["key"] if text[m.end():].lstrip().startswith(":") else _HL["str"], t))
        elif t in ("true", "false", "null"):
            out.append(_span(_HL["kw"], t))
        elif t[0] == "-" or t[0].isdigit():
            out.append(_span(_HL["num"], t))
        elif t in "{}[],:":
            out.append(_span(_HL["pun"], t))
        else:
            out.append(escape(t))
    return "".join(out)


def _hl_markup(text: str) -> str:
    out, pos = [], 0
    for m in _MARKUP_TOK.finditer(text):
        out.append(escape(text[pos:m.start()]))
        seg = m.group(0)
        out.append(_span(_HL["com"] if seg.startswith("<!--") else _HL["tag"], seg))
        pos = m.end()
    out.append(escape(text[pos:]))
    return "".join(out)


def _hl_generic(text: str) -> str:
    out, pos = [], 0
    for m in _GEN_TOK.finditer(text):
        out.append(escape(text[pos:m.start()]))
        c = _HL["str"] if m.group(1) else _HL["num"] if m.group(2) else _HL["kw"]
        out.append(_span(c, m.group(0)))
        pos = m.end()
    out.append(escape(text[pos:]))
    return "".join(out)


def _highlight_body(body: str, ctype: str) -> str:
    if len(body) > 400_000:          # keep very large bodies responsive — skip highlighting
        return escape(body)
    b = body.lstrip()
    if "json" in ctype or b[:1] in "{[":
        return _hl_json(body)
    if "html" in ctype or "xml" in ctype or b[:1] == "<":
        return _hl_markup(body)
    return _hl_generic(body)


def _format_response(r: dict) -> str:
    """Render an HTTP response as clean, syntax-highlighted HTML: status line, headers, body."""
    head = r.get("head", "")
    lines = head.split("\n")
    status_line = lines[0] if lines else ""
    status = r.get("status") or 0
    color = {2: "#24a148", 3: "#4589ff", 4: "#ff832b", 5: "#da1e28"}.get(status // 100, "#8d8d8d")
    out = [f"<div style='font-weight:600;color:{color};margin-bottom:6px'>{escape(status_line)}</div>"]
    hdr, ctype = [], ""
    for ln in lines[1:]:
        if ": " in ln:
            name, val = ln.split(": ", 1)
            if name.lower() == "content-type":
                ctype = val.lower()
            hdr.append(f"<span style='color:{_HL['hdr']};font-weight:600'>{escape(name)}:</span> {escape(val)}")
        elif ln.strip():
            hdr.append(escape(ln))
    if hdr:
        out.append("<div style='line-height:1.5'>" + "<br>".join(hdr) + "</div>")
    body = r.get("body", "")
    if body:
        out.append("<hr style='border:none;border-top:1px solid #8884;margin:8px 0'>")
        out.append(f"<pre style='white-space:pre-wrap;margin:0'>{_highlight_body(body, ctype)}</pre>")
    return "".join(out)


def sev_badge(sev: str) -> str:
    fg = "#161616" if sev == "medium" else "#ffffff"  # Carbon yellow needs dark text
    return (f"<span style='background:{SEV_COLOR.get(sev, '#8d8d8d')};color:{fg};"
            f"font-weight:600'>&nbsp;{sev.title()}&nbsp;</span>")


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
        m.addAction("Open in new tab", lambda: self.win.open_url(r["url"], new_tab=True))
        m.addSeparator()
        m.addAction("Copy URL", lambda: QGuiApplication.clipboard().setText(r["url"]))
        m.addAction("Copy as cURL", lambda: QGuiApplication.clipboard().setText(
            tools.to_curl(r["method"], r["url"], r.get("headers"))))
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _send_to_repeater(self, r):
        self.win.security.tools_tab.load_request(r["method"], r["url"], r.get("headers") or {})
        self.win.security.show_tab("Tools")


# =================================================================== Recon
class ReconTab(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self.items: list[tuple[str, str]] = []  # (url/text, tooltip)
        v = QVBoxLayout(self)
        row = QHBoxLayout()
        self.domain = QLineEdit()
        self.domain.setPlaceholderText("example.com")
        row.addWidget(QLabel("Domain"))
        row.addWidget(self.domain, 1)
        use = QPushButton("Use current")
        use.clicked.connect(self.use_current)
        row.addWidget(use)
        v.addLayout(row)
        row2 = QHBoxLayout()
        for label, fn in (("Subdomains (crt.sh)", self.subdomains), ("Wayback URLs", self.wayback),
                          ("robots / sitemap / security.txt", self.well_known)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            row2.addWidget(b)
        v.addLayout(row2)
        row3 = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter results…")
        self.filter.textChanged.connect(self._render)
        self.interesting = QCheckBox("Interesting only")
        self.interesting.toggled.connect(self._render)
        row3.addWidget(self.filter, 1)
        row3.addWidget(self.interesting)
        copy = QPushButton("Copy all")
        copy.clicked.connect(lambda: QGuiApplication.clipboard().setText("\n".join(t for t, _ in self._visible())))
        row3.addWidget(copy)
        v.addLayout(row3)
        self.list = mono(QListWidget())
        self.list.itemDoubleClicked.connect(self._open)
        self.list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.list.customContextMenuRequested.connect(self._list_menu)
        v.addWidget(self.list, 1)
        self.busy = BusyOverlay(self.list)
        self.status = QLabel("Passive sources only: certificate transparency logs and the Internet Archive.")
        self.status.setObjectName("Muted")
        self.status.setWordWrap(True)
        v.addWidget(self.status)

    def use_current(self):
        v = self.win.current_view()
        host = urlparse(v.url().toString()).hostname if v else ""
        if host:
            self.domain.setText(host[4:] if host.startswith("www.") else host)

    def _target(self) -> str | None:
        d = self.domain.text().strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
        if not d:
            self.use_current()
            d = self.domain.text().strip()
        if not d:
            return None
        eng = self.win.engagement
        if eng and eng.scope and not eng.in_scope(d):
            QMessageBox.warning(self, "Out of scope", f"{d} is not in the scope of '{eng.name}'.")
            return None
        return d

    def _run(self, label, fn, render):
        d = self._target()
        if not d:
            return
        self.status.setText(f"{label} for {d}…")
        self.busy.start(f"{label} for {d}…")

        def done(ok, r):
            self.busy.stop()
            render(d, r) if ok else self.status.setText(f"{label} failed: {r}")
        self.win.runner.run(fn, done, d)

    def subdomains(self):
        def render(d, names):
            eng = self.win.engagement
            self.items = [(n, "in scope" if eng and eng.in_scope(n) else "") for n in names]
            self.status.setText(f"{len(names)} unique hostnames for {d} from certificate transparency logs. "
                                "Double-click to open (check scope first).")
            self._render()
        self._run("Subdomains", intel.subdomains_crtsh, render)

    def wayback(self):
        def render(d, rows):
            self.items = [(r["original"], f"{r.get('statuscode')} · {r.get('mimetype')} · {r.get('timestamp', '')[:8]}")
                          for r in rows]
            n = sum(1 for u, _ in self.items if intel.INTERESTING_URL.search(u))
            self.status.setText(f"{len(rows)} archived URLs, {n} look interesting (params, backups, configs, APIs).")
            self._render()
        self._run("Wayback", intel.wayback_urls, render)

    def well_known(self):
        def render(d, r):
            self.items = []
            for name in ("security.txt", "robots.txt", "sitemap.xml"):
                x = r[name]
                self.items.append((f"── {name}: {'found' if x['found'] else 'not found'} (HTTP {x['status']})", ""))
                if name == "security.txt" and x["found"]:
                    self.items += [(f"   {line}", "disclosure policy") for line in x["text"].splitlines()[:30] if line.strip()]
            self.items += [(u, "Disallow in robots.txt") for u in r["disallowed"]]
            self.items += [(u, "sitemap") for u in r["sitemap_urls"]]
            self.status.setText(f"{len(r['disallowed'])} disallowed paths · {len(r['sitemap_urls'])} sitemap URLs. "
                                "security.txt tells you how the owner wants vulnerabilities reported.")
            self._render()
        self._run("Well-known files", lambda d: intel.well_known(f"https://{d}"), render)

    def _visible(self):
        f = self.filter.text().lower()
        for text, tip in self.items:
            if f and f not in text.lower():
                continue
            if self.interesting.isChecked() and not (intel.INTERESTING_URL.search(text) or tip == "in scope"):
                continue
            yield text, tip

    def _render(self):
        self.list.clear()
        for text, tip in self._visible():
            it = QListWidgetItem(text)
            it.setToolTip(tip)
            if tip == "in scope" or intel.INTERESTING_URL.search(text):
                it.setForeground(QBrush(QColor("#1e8e3e" if tip == "in scope" else "#fa7b17")))
            self.list.addItem(it)

    def _open(self, it):
        t = it.text().strip()
        if t.startswith("──"):
            return
        url = t if "://" in t else f"https://{t}"
        self.win.open_url(url, new_tab=True)

    def _host_of(self, it) -> str:
        t = it.text().strip()
        if t.startswith("──"):
            return ""
        return urlparse(t if "://" in t else "https://" + t).hostname or t

    def _list_menu(self, pos):
        it = self.list.itemAt(pos)
        if not it or it.text().strip().startswith("──"):
            return
        t = it.text().strip()
        url = t if "://" in t else f"https://{t}"
        host = self._host_of(it)
        m = QMenu(self)
        m.addAction("Open in new tab", lambda: self.win.open_url(url, new_tab=True))
        m.addAction("Scan this host", lambda: (self.win.open_url(url, new_tab=True),
                                               self.win.security.show_tab("Overview")))
        m.addSeparator()
        m.addAction("Copy", lambda: QGuiApplication.clipboard().setText(t))
        m.addAction("Copy all shown", lambda: QGuiApplication.clipboard().setText(
            "\n".join(x for x, _ in self._visible())))
        eng = self.win.engagement
        if eng and host and not eng.in_scope(host):
            m.addSeparator()
            m.addAction(f"Add {host} to engagement scope", lambda: self._add_scope(host))
        m.exec(self.list.viewport().mapToGlobal(pos))

    def _add_scope(self, host):
        eng = self.win.engagement
        if eng and host not in eng.scope:
            eng.scope.append(host)
            self.win.store.save_engagement(eng)
            self.win.toast(f"Added {host} to scope of '{eng.name}'")
            self._render()


# =================================================================== Tools
class ToolsTab(QWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self._confirmed_hosts: set[str] = set()  # out-of-scope hosts the user already OK'd in the Repeater
        v = QVBoxLayout(self)
        v.setContentsMargins(0, 0, 0, 0)
        v.setSpacing(6)
        row = QHBoxLayout()
        row.addWidget(QLabel("Tool"))
        self._sel = QComboBox()  # compact selector instead of overflowing horizontal tabs
        self._sel.currentIndexChanged.connect(lambda i: self._stack.setCurrentIndex(i))
        row.addWidget(self._sel, 1)
        v.addLayout(row)
        self._stack = QStackedWidget()
        v.addWidget(self._stack, 1)
        self._tool_names = []
        for name, builder in (("Decoder", self._decoder), ("JWT", self._jwt), ("Hash", self._hash),
                              ("Repeater", self._repeater), ("Match & Replace", self._rewrite),
                              ("Comparer", self._comparer), ("Sequencer", self._sequencer),
                              ("AI Triage", self._triage)):
            self._stack.addWidget(builder())
            self._sel.addItem(name)
            self._tool_names.append(name)

    def _select_tool(self, name):
        if name in self._tool_names:
            self._sel.setCurrentIndex(self._tool_names.index(name))

    # ---------------------------------------------------------------- AI Triage (scope-gated, HITL)
    def _triage(self):
        w = QWidget()
        v = QVBoxLayout(w)
        self.tr_scope = QLabel("")
        self.tr_scope.setObjectName("Muted")
        self.tr_scope.setWordWrap(True)
        v.addWidget(self.tr_scope)
        self.tr_in = mono(QPlainTextEdit())
        self.tr_in.setPlaceholderText("Paste an HTTP request/response pair, API schema, or source code to triage…")
        v.addWidget(self.tr_in, 1)
        row = QHBoxLayout()
        b_load = QPushButton("Load last Repeater request")
        b_load.clicked.connect(lambda: self.tr_in.setPlainText(
            f"{self.r_method.currentText()} {self.r_url.text()}\n{self.r_headers.toPlainText()}\n\n{self.r_body.toPlainText()}"))
        self.tr_go = QPushButton("Analyze (non-destructive)")
        self.tr_go.setObjectName("Primary")
        self.tr_go.clicked.connect(self._do_triage)
        row.addWidget(b_load)
        row.addStretch(1)
        row.addWidget(self.tr_go)
        v.addLayout(row)
        self.tr_out = QTextBrowser()
        self.tr_out.setOpenLinks(False)
        v.addWidget(self.tr_out, 1)
        self.tr_busy = BusyOverlay(self.tr_out)
        return w

    def _do_triage(self):
        from .security import triage
        eng = self.win.engagement
        scope = ", ".join(eng.scope) if eng and eng.scope else ""
        self.tr_scope.setText(f"Authorized scope: <b>{escape(scope) or 'none set — set an engagement scope first'}</b> · "
                              "analysis only, no requests are sent, benign verification steps only.")
        key = self.win.settings.value("ai/api_key", "", type=str)
        model = self.win.settings.value("ai/model", "kim-modeling-sp-001", type=str)
        if not key:
            self.tr_out.setHtml("<p>No API key set. Add one in <b>Settings → General → AI Triage</b> "
                                "(your own API key, stored only on this device).</p>")
            return
        content = self.tr_in.toPlainText()
        self.tr_go.setEnabled(False)
        self.tr_busy.start("Analyzing…")

        def done(ok, r):
            self.tr_go.setEnabled(True)
            self.tr_busy.stop()
            if ok:
                self.tr_out.setHtml("<pre style='white-space:pre-wrap'>" + escape(r) + "</pre>")
            else:
                self.tr_out.setHtml(f"<p style='color:#da1e28'>Triage failed: {escape(str(r))}</p>")
        self.win.runner.run(lambda: triage.triage(content, scope, key, model), done)

    # ---------------------------------------------------------------- Comparer
    def _comparer(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel("Diff two requests/responses word-by-word (paste or send from Repeater/Traffic)."))
        split = QSplitter(Qt.Orientation.Horizontal)
        self.cmp_a = mono(QPlainTextEdit())
        self.cmp_a.setPlaceholderText("A")
        self.cmp_b = mono(QPlainTextEdit())
        self.cmp_b.setPlaceholderText("B")
        split.addWidget(self.cmp_a)
        split.addWidget(self.cmp_b)
        v.addWidget(split, 1)
        row = QHBoxLayout()
        b = QPushButton("Compare")
        b.setObjectName("Primary")
        b.clicked.connect(self._do_compare)
        row.addWidget(b)
        row.addStretch(1)
        v.addLayout(row)
        self.cmp_out = QTextBrowser()
        v.addWidget(self.cmp_out, 1)
        return w

    def _do_compare(self):
        a, b = self.cmp_a.toPlainText(), self.cmp_b.toPlainText()
        st = tools.diff_stats(a, b)
        parts = [f"<p class='meta' style='color:#8d8d8d'>Similarity {st['ratio']}% · A {st['len_a']} chars · B {st['len_b']} chars</p><pre style='white-space:pre-wrap;margin:0'>"]
        for op, text in tools.word_diff(a, b):
            t = escape(text)
            if op == "equal":
                parts.append(t)
            elif op == "insert":
                parts.append(f"<span style='background:rgba(36,161,72,.28)'>{t}</span>")
            else:  # delete
                parts.append(f"<span style='background:rgba(218,30,40,.28);text-decoration:line-through'>{t}</span>")
        parts.append("</pre>")
        self.cmp_out.setHtml("".join(parts))

    # ---------------------------------------------------------------- Sequencer
    def _sequencer(self):
        w = QWidget()
        v = QVBoxLayout(w)
        v.addWidget(QLabel("Assess the randomness of session / CSRF / reset tokens. Paste tokens, one per line."))
        self.seq_in = mono(QPlainTextEdit())
        self.seq_in.setPlaceholderText("one token per line…")
        v.addWidget(self.seq_in, 1)
        b = QPushButton("Analyze randomness")
        b.setObjectName("Primary")
        b.clicked.connect(self._do_sequence)
        v.addWidget(b)
        self.seq_out = QTextBrowser()
        v.addWidget(self.seq_out, 1)
        return w

    def _do_sequence(self):
        r = tools.analyze_tokens(self.seq_in.toPlainText().splitlines())
        if r.get("error"):
            self.seq_out.setHtml(f"<p style='color:#da1e28'>{escape(r['error'])}</p>")
            return
        vq = r["quality_pct"]
        color = "#24a148" if vq >= 85 else "#ff832b" if vq >= 60 else "#da1e28"
        self.seq_out.setHtml(
            f"<p style='font-size:15px;color:{color};font-weight:600'>{escape(r['verdict'])}</p>"
            f"<p><b>{r['entropy_bits']} bits</b> of entropy (of ~{r['max_bits']} max) · quality {vq}%</p>"
            f"<p class='meta' style='color:#8d8d8d'>{r['count']} tokens · {r['duplicates']} duplicates · "
            f"length {r['common_length']}{'' if r['length_consistent'] else ' (varies)'} · "
            f"charset {r['charset_size']} chars</p>"
            f"<p class='meta' style='color:#8d8d8d'>Per-character entropy (bits): {escape(str(r['pos_entropy']))}</p>")

    def _decoder(self):
        w = QWidget()
        v = QVBoxLayout(w)
        self.d_in = mono(QPlainTextEdit())
        self.d_in.setPlaceholderText("Paste text to encode / decode")
        v.addWidget(self.d_in, 1)
        row = QHBoxLayout()
        self.d_op = QComboBox()
        self.d_op.addItems(list(tools.TRANSFORMS))
        row.addWidget(self.d_op, 1)
        for label, fn in (("Apply", self._apply), ("Smart decode", self._smart), ("↑ Use output", self._swap)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            row.addWidget(b)
        v.addLayout(row)
        self.d_out = mono(QPlainTextEdit())
        self.d_out.setReadOnly(True)
        v.addWidget(self.d_out, 1)
        return w

    def _apply(self):
        self.d_out.setPlainText(tools.transform(self.d_op.currentText(), self.d_in.toPlainText()))

    def _smart(self):
        steps = tools.smart_decode(self.d_in.toPlainText())
        self.d_out.setPlainText("\n\n".join(f"── {name} ──\n{val}" for name, val in steps) or "Nothing to decode.")

    def _swap(self):
        out = self.d_out.toPlainText()
        if "── " in out:
            out = out.rsplit("──\n", 1)[-1]
        self.d_in.setPlainText(out)

    def _jwt(self):
        w = QWidget()
        v = QVBoxLayout(w)
        self.j_in = mono(QPlainTextEdit())
        self.j_in.setPlaceholderText("Paste a JWT (eyJ…)")
        self.j_in.setMaximumHeight(110)
        self.j_in.textChanged.connect(self._decode_jwt)
        v.addWidget(self.j_in)
        self.j_out = mono(QPlainTextEdit())
        self.j_out.setReadOnly(True)
        v.addWidget(self.j_out, 1)
        return w

    def _decode_jwt(self):
        t = self.j_in.toPlainText().strip()
        if not t:
            self.j_out.clear()
            return
        try:
            d = tools.decode_jwt(t)
            self.j_out.setPlainText("NOTES\n" + "\n".join(f"• {n}" for n in d["notes"]) +
                                    "\n\nHEADER\n" + json.dumps(d["header"], indent=2) +
                                    "\n\nPAYLOAD\n" + json.dumps(d["payload"], indent=2) +
                                    f"\n\nSignature present: {d['signature_present']} (not verified)")
        except Exception as e:  # noqa: BLE001
            self.j_out.setPlainText(f"Can't decode: {e}")

    def _hash(self):
        w = QWidget()
        v = QVBoxLayout(w)
        self.h_in = mono(QLineEdit())
        self.h_in.setPlaceholderText("Paste a hash to identify, or text to hash")
        self.h_in.textChanged.connect(self._hash_update)
        v.addWidget(self.h_in)
        self.h_out = mono(QPlainTextEdit())
        self.h_out.setReadOnly(True)
        v.addWidget(self.h_out, 1)
        return w

    def _hash_update(self):
        s = self.h_in.text()
        if not s:
            self.h_out.clear()
            return
        lines = ["IDENTIFY (if this is a hash)", "  " + " / ".join(tools.identify_hash(s)), "", "HASH OF THIS TEXT"]
        lines += [f"  {k:7} {v}" for k, v in tools.compute_hashes(s).items()]
        self.h_out.setPlainText("\n".join(lines))

    def _repeater(self):
        w = QWidget()
        v = QVBoxLayout(w)
        # --- session tabs: each request is its own tab, like Burp/Caido Repeater, so opening a new
        #     one (or sending from Traffic) never overwrites an existing test. State is kept per tab.
        self.r_sessions: list[dict] = []
        self.r_current = -1
        self._r_switching = False
        tabrow = QHBoxLayout()
        tabrow.setSpacing(2)
        self.r_tabs = QTabBar()
        self.r_tabs.setTabsClosable(True)
        self.r_tabs.setExpanding(False)
        self.r_tabs.setElideMode(Qt.TextElideMode.ElideRight)
        self.r_tabs.setUsesScrollButtons(True)
        self.r_tabs.currentChanged.connect(self._r_tab_changed)
        self.r_tabs.tabCloseRequested.connect(self._r_close_tab)
        tabrow.addWidget(self.r_tabs, 1)
        r_add = QToolButton()
        r_add.setText("+")
        r_add.setToolTip("New Repeater tab")
        r_add.setFixedSize(26, 24)
        r_add.clicked.connect(lambda: self._r_new_session())
        tabrow.addWidget(r_add, 0)
        v.addLayout(tabrow)
        row = QHBoxLayout()
        self.r_method = QComboBox()
        self.r_method.addItems(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
        self.r_method.setEditable(True)
        row.addWidget(self.r_method)
        self.r_url = mono(QLineEdit())
        self.r_url.setPlaceholderText("https://target/api/…")
        row.addWidget(self.r_url, 1)
        self.r_send = QPushButton("Send")
        self.r_send.setObjectName("Primary")
        self.r_send.clicked.connect(self._send)
        row.addWidget(self.r_send)
        v.addLayout(row)

        pane = _pane  # shared helper: same spacing everywhere

        split = QSplitter(Qt.Orientation.Vertical)
        self.r_headers = mono(QPlainTextEdit())
        self.r_headers.setPlaceholderText("Header: value (one per line)")
        self._hdr_hl = HeaderHighlighter(self.r_headers)  # colorize header names
        self.r_body = mono(QPlainTextEdit())
        self.r_body.setPlaceholderText("Request body")
        # response area with a Raw / Preview toggle (Preview renders HTML with JavaScript OFF — safe)
        from PySide6.QtWebEngineWidgets import QWebEngineView
        from PySide6.QtWebEngineCore import QWebEngineSettings
        self.r_resp = mono(QTextBrowser())
        self.r_resp.setOpenLinks(False)
        self.r_preview = QWebEngineView()
        self.r_preview.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, False)
        self.r_resp_stack = QStackedWidget()
        self.r_resp_stack.addWidget(self.r_resp)
        self.r_resp_stack.addWidget(self.r_preview)
        self.r_busy = BusyOverlay(self.r_resp_stack)
        self.r_seg = {}

        def resp_toggle(head):
            for key, label in (("raw", "Raw"), ("preview", "Preview")):
                b = QPushButton(label)
                b.setObjectName("Segment")
                b.setCheckable(True)
                b.setFixedHeight(24)
                b.setMaximumWidth(80)
                b.clicked.connect(lambda _c, k=key: self._resp_view(k))
                head.addWidget(b)
                self.r_seg[key] = b
            self.r_seg["raw"].setChecked(True)

        split.addWidget(pane("Request headers", self.r_headers))
        split.addWidget(pane("Request body", self.r_body))
        split.addWidget(pane("Response", self.r_resp_stack, resp_toggle))
        split.setSizes([120, 80, 340])
        v.addWidget(split, 1)
        row2 = QHBoxLayout()
        self.r_follow = QCheckBox("Follow redirects")
        row2.addWidget(self.r_follow)
        row2.addStretch(1)
        curl = QPushButton("Copy as cURL")
        curl.clicked.connect(lambda: QGuiApplication.clipboard().setText(tools.to_curl(
            self.r_method.currentText(), self.r_url.text(), tools.parse_headers(self.r_headers.toPlainText()),
            self.r_body.toPlainText())))
        row2.addWidget(curl)
        v.addLayout(row2)
        # relabel the active tab as the target changes, so tabs stay recognizable
        self.r_url.editingFinished.connect(self._r_relabel)
        self.r_method.currentTextChanged.connect(lambda *_: self._r_relabel())
        self._r_new_session()  # start with one empty session
        return w

    # ---------------------------------------------------------------- Repeater sessions
    def _r_label(self, method, url):
        host = urlparse(url).hostname or ""
        tail = ((host + (urlparse(url).path or "")).rstrip("/"))[:24]
        return (f"{method} {tail}".strip() if tail else f"{method} (empty)")

    def _r_blank(self):
        return {"method": "GET", "url": "", "headers": "", "body": "", "follow": False,
                "resp_html": "", "last_body": ""}

    def _r_capture(self):
        """Write the live editors into the current session dict."""
        if 0 <= self.r_current < len(self.r_sessions):
            s = self.r_sessions[self.r_current]
            s["method"] = self.r_method.currentText()
            s["url"] = self.r_url.text()
            s["headers"] = self.r_headers.toPlainText()
            s["body"] = self.r_body.toPlainText()
            s["follow"] = self.r_follow.isChecked()
            s["resp_html"] = self.r_resp.toHtml()
            s["last_body"] = getattr(self, "_last_body", "")

    def _r_restore(self, i):
        """Load session i into the live editors."""
        s = self.r_sessions[i]
        self.r_method.setCurrentText(s["method"])
        self.r_url.setText(s["url"])
        self.r_headers.setPlainText(s["headers"])
        self.r_body.setPlainText(s["body"])
        self.r_follow.setChecked(s["follow"])
        self._last_body = s["last_body"]
        if s["resp_html"]:
            self.r_resp.setHtml(s["resp_html"])
        else:
            self.r_resp.clear()
        self._resp_view("raw")

    def _r_tab_changed(self, i):
        if self._r_switching or i < 0 or i >= len(self.r_sessions):
            return
        self.r_current = i
        self._r_switching = True   # suppress relabel churn while we repopulate the editors
        self._r_restore(i)
        self._r_switching = False

    def _r_new_session(self, method="GET", url="", headers="", body=""):
        self._r_capture()
        self.r_sessions.append({**self._r_blank(), "method": method or "GET",
                                "url": url, "headers": headers, "body": body})
        self._r_switching = True
        idx = self.r_tabs.addTab(self._r_label(method or "GET", url))
        self.r_tabs.setCurrentIndex(idx)
        self.r_current = idx
        self._r_restore(idx)
        self._r_switching = False

    def _r_close_tab(self, i):
        if i < 0 or i >= len(self.r_sessions):
            return
        if len(self.r_sessions) == 1:  # keep one tab alive — just reset it
            self.r_sessions[0] = self._r_blank()
            self._last_body = ""
            self._r_restore(0)
            self.r_tabs.setTabText(0, self._r_label("GET", ""))
            return
        del self.r_sessions[i]
        self._r_switching = True
        self.r_tabs.removeTab(i)
        self._r_switching = False
        self.r_current = self.r_tabs.currentIndex()
        if 0 <= self.r_current < len(self.r_sessions):
            self._r_restore(self.r_current)

    def _r_relabel(self):
        if self._r_switching:
            return
        if 0 <= self.r_current < self.r_tabs.count():
            self.r_tabs.setTabText(self.r_current, self._r_label(self.r_method.currentText(), self.r_url.text()))

    # ---------------------------------------------------------------- Match & Replace
    def _rewrite(self):
        from .security.rewrite import Rule
        w = QWidget()
        v = QVBoxLayout(w)
        info = QLabel("Rewrite request headers for hosts <b>in the active engagement's scope</b> (like Burp/Caido "
                      "Match &amp; Replace). Useful for a custom User-Agent, an auth header, or X-Forwarded-For tests.")
        info.setWordWrap(True)
        info.setObjectName("Muted")
        v.addWidget(info)
        self.rw_table = QTreeWidget()
        self.rw_table.setHeaderLabels(["On", "Name", "Host", "Header", "Match (regex)", "Value", ""])
        self.rw_table.setRootIsDecorated(False)
        for i, wdt in enumerate((40, 110, 130, 130, 130, 140, 70)):
            self.rw_table.setColumnWidth(i, wdt)
        v.addWidget(self.rw_table, 1)
        row = QHBoxLayout()
        for label, fn in (("Add rule", self._rw_add), ("Remove", self._rw_remove)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch(1)
        self.rw_status = QLabel("")
        self.rw_status.setObjectName("Muted")
        row.addWidget(self.rw_status)
        v.addLayout(row)
        self._rw_refresh()
        return w

    def _rw_refresh(self):
        self.rw_table.clear()
        if not hasattr(self.win, "rules"):
            return
        for idx, r in enumerate(self.win.rules.rules):
            it = QTreeWidgetItem(["", r.name, r.host_glob, r.header, r.match, r.replace])
            it.setData(0, Qt.ItemDataRole.UserRole, idx)
            it.setCheckState(0, Qt.CheckState.Checked if r.enabled else Qt.CheckState.Unchecked)
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsEditable | Qt.ItemFlag.ItemIsUserCheckable)
            self.rw_table.addTopLevelItem(it)
        eng = self.win.engagement
        self.rw_status.setText(f"Scope: {eng.name}" if eng else "No engagement — rules apply to no hosts until you pick one")
        try:
            self.rw_table.itemChanged.disconnect()
        except RuntimeError:
            pass
        self.rw_table.itemChanged.connect(self._rw_edited)

    def _rw_edited(self, item, col):
        from .security.rewrite import Rule
        idx = item.data(0, Qt.ItemDataRole.UserRole)
        if idx is None or idx >= len(self.win.rules.rules):
            return
        r: Rule = self.win.rules.rules[idx]
        r.enabled = item.checkState(0) == Qt.CheckState.Checked
        r.name, r.host_glob, r.header, r.match, r.replace = (item.text(i) for i in range(1, 6))
        self.win.save_rules()

    def _rw_add(self):
        from .security.rewrite import Rule
        self.win.rules.rules.append(Rule(True, "New rule", "*", "User-Agent", "", "HiddenBrowser/1.0"))
        self.win.save_rules()
        self._rw_refresh()

    def _rw_remove(self):
        it = self.rw_table.currentItem()
        if it is not None:
            idx = it.data(0, Qt.ItemDataRole.UserRole)
            if idx is not None and idx < len(self.win.rules.rules):
                del self.win.rules.rules[idx]
                self.win.save_rules()
                self._rw_refresh()

    def load_request(self, method, url, headers: dict):
        self._select_tool("Repeater")
        # open each sent request in its own tab so earlier ones are never lost
        self._r_new_session(method or "GET", url, "\n".join(f"{k}: {v}" for k, v in headers.items()))
        self._r_relabel()

    def _send(self):
        url = self.r_url.text().strip()
        host = urlparse(url).hostname or ""
        if not host:
            return
        eng = self.win.engagement
        # allow any target; if an engagement is set and the host is out of scope, confirm once (don't hard-block)
        if eng and eng.scope and not eng.in_scope(host) and host not in self._confirmed_hosts:
            ok = QMessageBox.question(
                self, "Send to out-of-scope host?",
                f"<b>{host}</b> is not in the scope of engagement '{eng.name}'.\n\n"
                "Only send requests to systems you are authorized to test. Send anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if ok != QMessageBox.StandardButton.Yes:
                return
            self._confirmed_hosts.add(host)
        self.r_send.setEnabled(False)
        self.r_resp.clear()
        self.r_busy.start("Sending request…")
        args = (self.r_method.currentText(), url, self.r_headers.toPlainText(), self.r_body.toPlainText(),
                self.win.proxies(), self.win.verify_tls(), self.r_follow.isChecked())

        def done(ok, r):
            self.r_send.setEnabled(True)
            self.r_busy.stop()
            if ok:
                self.r_resp.setHtml(_format_response(r))
                self._last_body = r.get("body", "")
            else:
                self.r_resp.setHtml(f"<pre style='color:#da1e28'>Error: {escape(str(r))}</pre>")
                self._last_body = ""
            self._resp_view("raw")
            self._r_capture()   # keep the response with its session tab
            self._r_relabel()
        self.win.runner.run(lambda: tools.send_request(*args), done)

    def _resp_view(self, key):
        for k, b in self.r_seg.items():
            b.setChecked(k == key)
        if key == "preview":
            self.r_resp_stack.setCurrentWidget(self.r_preview)
            self.r_preview.setHtml(getattr(self, "_last_body", "") or "<p style='color:gray'>No response yet.</p>")
        else:
            self.r_resp_stack.setCurrentWidget(self.r_resp)


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


# =================================================================== Shields
class ShieldsTab(QWidget):
    CATS = [("ads", "Ads"), ("trackers", "Trackers"), ("malware", "Malware"), ("phishing", "Phishing"),
            ("youtube", "YouTube ads"), ("popups", "Pop-ups"), ("params", "Tracking params removed"),
            ("upgraded", "Upgraded to HTTPS")]
    # (key, short label, details shown as tooltip) — short labels keep the panel usable when narrow
    TOGGLES = [("ads", "Block ads", ""),
               ("antifp", "Resist fingerprinting", "Canvas / WebGL / audio noise. Applies to new tabs."),
               ("trackers", "Block trackers", "Filter lists + HackPi beacon heuristics"),
               ("malware", "Block malware && phishing", "Blocks known malware and phishing sites"),
               ("linkguard", "Smart link check", "Phishing heuristics on links you open"),
               ("popups", "Block ad pop-ups", ""),
               ("params", "Strip tracking parameters", "Removes utm_*, fbclid, gclid… from links"),
               ("youtube", "Remove YouTube ads", "Applies to new tabs")]

    def __init__(self, win):
        super().__init__()
        self.win = win
        v = QVBoxLayout(self)
        head = QHBoxLayout()
        self.site = QLabel("")
        self.site.setWordWrap(True)
        head.addWidget(self.site, 1)
        self.site_toggle = QCheckBox("Shields up for this site")
        self.site_toggle.toggled.connect(self._site_toggled)
        head.addWidget(self.site_toggle)
        v.addLayout(head)
        self.grid = QLabel("")
        self.grid.setTextFormat(Qt.TextFormat.RichText)
        self.grid.setWordWrap(True)
        self._stat_cols = 4
        v.addWidget(self.grid)
        self.list = QTreeWidget()
        self.list.setHeaderLabels(["Blocked", "Request"])
        self.list.setRootIsDecorated(False)
        self.list.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.list.itemDoubleClicked.connect(lambda it, _c: QGuiApplication.clipboard().setText(it.text(1)))
        self.list.setToolTip("Double-click to copy the URL")
        v.addWidget(self.list, 1)

        opts = QLabel("<b>Protection</b>")
        v.addWidget(opts)
        hint = QLabel("Tip: to inspect a site's ads for malvertising, turn off <b>Shields up for this site</b> "
                      "above (loads ads on that site only), or untick <b>Block ads</b> globally.")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        v.addWidget(hint)
        self.checks = {}
        for key, label, tip in self.TOGGLES:
            c = QCheckBox(label)
            if tip:
                c.setToolTip(tip)
            c.setChecked(win.shields.enabled(key))
            c.toggled.connect(lambda on, k=key: (win.shields.set_enabled(k, on), self._reload_hint()))
            v.addWidget(c)
            self.checks[key] = c

        v.addWidget(QLabel("<b>Encryption</b>"))
        self.https = QCheckBox("HTTPS-Only mode")
        self.https.setToolTip("Upgrade every connection to HTTPS")
        self.https.setChecked(win.https_only())
        self.https.toggled.connect(lambda on: win.settings.setValue("privacy/https_only", on))
        v.addWidget(self.https)
        v.addWidget(QLabel("Encrypted DNS (DNS-over-HTTPS)"))
        row = QHBoxLayout()
        self.doh_mode = QComboBox()
        for key, label in (("secure", "On (fallback to system DNS)"), ("strict", "Strict (encrypted only)"), ("off", "Off")):
            self.doh_mode.addItem(label, key)
        self.doh_mode.setCurrentIndex(max(0, self.doh_mode.findData(win.settings.value("privacy/doh_mode", "secure"))))
        self.doh_prov = QComboBox()
        for key, (label, _url) in win.DOH.items():
            self.doh_prov.addItem(label, key)
        self.doh_prov.setCurrentIndex(max(0, self.doh_prov.findData(win.settings.value("privacy/doh_provider", "cloudflare"))))
        for box, key in ((self.doh_mode, "privacy/doh_mode"), (self.doh_prov, "privacy/doh_provider")):
            box.currentIndexChanged.connect(lambda _i, b=box, k=key: (win.settings.setValue(k, b.currentData()), win.apply_dns()))
        for box in (self.doh_mode, self.doh_prov):  # may shrink below their longest item
            box.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
            box.setMinimumContentsLength(8)
            box.view().setMinimumWidth(240)
        row.addWidget(self.doh_mode, 1)
        row.addWidget(self.doh_prov, 1)
        v.addLayout(row)
        if win.tor:
            self.doh_mode.setEnabled(False)
            self.doh_prov.setEnabled(False)
            self.doh_mode.setToolTip("Tor windows resolve DNS inside the Tor network")

        foot = QHBoxLayout()
        self.lists = QLabel("")
        self.lists.setObjectName("Muted")
        self.lists.setWordWrap(True)
        foot.addWidget(self.lists, 1)
        upd = QPushButton("Update lists")
        upd.clicked.connect(self._update_lists)
        upd.setMinimumWidth(130)
        foot.addWidget(upd, 0, Qt.AlignmentFlag.AlignRight)
        v.addLayout(foot)
        if win.tor:
            trow = QHBoxLayout()
            self.tor_label = QLabel("")
            self.tor_label.setWordWrap(True)
            trow.addWidget(self.tor_label, 1)
            nb = QPushButton("New identity")
            nb.clicked.connect(win.tor_new_identity)
            db = QPushButton("Disconnect Tor")
            db.setObjectName("Danger")
            db.clicked.connect(win.disconnect_tor)
            for b in (nb, db):  # same width + same (right) side, aligned with Update lists above
                b.setMinimumWidth(130)
                trow.addWidget(b, 0, Qt.AlignmentFlag.AlignRight)
            v.addLayout(trow)
        self.refresh()

    def resizeEvent(self, ev):  # re-flow the counters when the panel is resized
        super().resizeEvent(ev)
        if max(2, min(4, (self.width() - 32) // 120)) != self._stat_cols:
            self.refresh()

    def _reload_hint(self):
        self.win.toast("Shield settings changed: reload the page to apply")

    def sync_from_settings(self):
        """Reflect settings changed elsewhere (the Settings dialog) in these controls."""
        for key, cb in self.checks.items():
            cb.blockSignals(True)
            cb.setChecked(self.win.shields.enabled(key))
            cb.blockSignals(False)
        self.https.blockSignals(True)
        self.https.setChecked(self.win.https_only())
        self.https.blockSignals(False)

    def _site_toggled(self, on):
        host = self._host()
        if host:
            self.win.shields.set_site_enabled(host, on)
            v = self.win.current_view()
            if v:
                v.reload()

    def _host(self) -> str:
        v = self.win.current_view() if hasattr(self.win, "tabbar") else None
        return v.url().host() if v and v.url().scheme().startswith("http") else ""

    def _update_lists(self):
        self.lists.setText("Downloading filter lists…")
        from . import shields as sm
        self.win.runner.run(lambda: sm.build_engines(sm.fetch_lists(self.win.shields.cache)), self.win._filters_ready)

    def refresh(self):
        v = self.win.current_view() if hasattr(self.win, "tabbar") else None
        st = v.stats if v else None
        host = self._host()
        self.site.setText(f"<b>{escape(host)}</b>" if host else "<span style='color:gray'>No website open</span>")
        self.site_toggle.blockSignals(True)
        self.site_toggle.setEnabled(bool(host))
        self.site_toggle.setChecked(self.win.shields.site_enabled(host) if host else True)
        self.site_toggle.blockSignals(False)
        cells = []
        for key, label in self.CATS:
            n = st.counts.get(key, 0) if st else 0
            color = "#da1e28" if key in ("malware", "phishing") and n else ("#4589ff" if n else "#8d8d8d")
            cells.append(f"<td style='padding:6px 14px 6px 0'><span style='font-size:20px;font-weight:300;color:{color}'>{n}"
                         f"</span><br><span style='color:gray;font-size:11px'>{label}</span></td>")
        per = max(2, min(4, (self.width() - 32) // 120))  # columns that fit the panel width
        self._stat_cols = per
        rows = "".join("<tr>" + "".join(cells[i:i + per]) + "</tr>" for i in range(0, len(cells), per))
        total = self.win.shields.total_blocked
        self.grid.setText(f"<table>{rows}</table><span style='color:gray'>{total:,} blocked since install</span>")
        self.list.clear()
        for cat, url, rtype in reversed((st.blocked if st else [])[-500:]):
            it = QTreeWidgetItem([cat, url])
            it.setToolTip(1, f"{rtype}: {url}")
            if cat in ("malware", "phishing", "suspicious"):
                it.setForeground(0, QBrush(QColor("#da1e28")))
            self.list.addTopLevelItem(it)
        rules = self.win.shields.rule_counts()
        r = " · ".join(f"{k} {n:,}" for k, n in rules.items()) or "not downloaded yet"
        self.lists.setText(f"Filter rules: {r} · updated {self.win.shields.last_updated()}.")
        if self.win.tor and hasattr(self, "tor_label"):
            self.tor_label.setText(f"<b>Tor circuit:</b> {escape(self.win.tor.circuit_summary())}")

    def showEvent(self, e):
        super().showEvent(e)
        self.refresh()


# =================================================================== dock
class SiteMapTab(QWidget):
    """Tree of hosts → paths discovered from observed traffic (passive — just what you browsed)."""

    def __init__(self, win):
        super().__init__()
        self.win = win
        self._discovered: dict[str, dict[str, dict]] = {}   # host -> path -> {methods, url, source}
        v = QVBoxLayout(self)
        intro = QLabel("Passive discovery — URLs seen while you browse, plus what a site publishes about itself "
                       "(robots.txt + sitemap.xml). No wordlists, no directory brute-forcing.")
        intro.setWordWrap(True)
        intro.setObjectName("Muted")
        v.addWidget(intro)
        row = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter host / path…")
        self.filter.textChanged.connect(self._build)
        row.addWidget(self.filter, 1)
        self.scope_only = QCheckBox("In-scope only")
        self.scope_only.toggled.connect(self._build)
        row.addWidget(self.scope_only)
        self.b_discover = QPushButton("Discover current site")
        self.b_discover.setToolTip("Fetch robots.txt + sitemap.xml for the current site (scope-gated)")
        self.b_discover.clicked.connect(self._discover)
        row.addWidget(self.b_discover)
        self.b_export = QPushButton("Export…")
        self.b_export.clicked.connect(self._export)
        row.addWidget(self.b_export)
        b = QPushButton("Refresh")
        b.clicked.connect(self._build)
        row.addWidget(b)
        clr = QPushButton("Clear")
        clr.setToolTip("Clear the site map (the Traffic history is kept)")
        clr.clicked.connect(self._clear)
        row.addWidget(clr)
        v.addLayout(row)
        self._cleared_after = None  # last traffic row at the moment of "Clear"; only newer rows are mapped
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Path", "Methods", "Source"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.itemDoubleClicked.connect(self._open)
        v.addWidget(self.tree, 1)
        self.count = QLabel("")
        self.count.setObjectName("Muted")
        v.addWidget(self.count)

    def showEvent(self, e):
        super().showEvent(e)
        self._build()

    def _clear(self):
        rows = self.win.security.traffic.model.rows
        self._cleared_after = rows[-1] if rows else None
        self._discovered.clear()
        self._build()
        self.win.toast("Site map cleared — new pages you browse will appear here")

    def _rows_since_clear(self, rows):
        mark = self._cleared_after
        if mark is None:
            return rows
        for i in range(len(rows) - 1, -1, -1):
            if rows[i] is mark:
                return rows[i + 1:]
        return rows  # marker rotated out of the traffic buffer: everything left is newer

    def _in_scope_host(self, host: str) -> bool:
        eng = self.win.engagement
        return eng.in_scope(host) is not False if eng and eng.scope else True

    def _build(self):
        f = self.filter.text().lower().strip()
        self.tree.clear()
        rows = self._rows_since_clear(self.win.security.traffic.model.rows if hasattr(self.win, "security") else [])
        hosts: dict[str, dict] = {}

        def add(host, path, method, url, source):
            if not host:
                return
            h = hosts.setdefault(host, {})
            e = h.setdefault(path, {"methods": set(), "url": url, "sources": set()})
            if method:
                e["methods"].add(method)
            e["sources"].add(source)

        for r in rows:  # observed traffic
            if r["in_scope"] is not True and self.scope_only.isChecked():
                continue
            if f and f not in r["host"].lower() and f not in r["path"].lower():
                continue
            add(r["host"], r["path"], r["method"], r["url"], "browsed")
        for host, paths in self._discovered.items():  # passive discovery (robots/sitemap)
            if self.scope_only.isChecked() and not self._in_scope_host(host):
                continue
            for path, e in paths.items():
                if f and f not in host.lower() and f not in path.lower():
                    continue
                add(host, path, "", e["url"], e["source"])
        total = 0
        for host in sorted(hosts):
            paths = hosts[host]
            top = QTreeWidgetItem([host, f"{len(paths)} paths", ""])
            fnt = top.font(0)
            fnt.setBold(True)
            top.setFont(0, fnt)
            for path in sorted(paths):
                e = paths[path]
                it = QTreeWidgetItem([path, ",".join(sorted(m for m in e["methods"] if m)), ", ".join(sorted(e["sources"]))])
                it.setData(0, Qt.ItemDataRole.UserRole, e["url"])
                it.setToolTip(0, e["url"])
                top.addChild(it)
                total += 1
            self.tree.addTopLevelItem(top)
            top.setExpanded(len(paths) <= 40)
        disc = sum(len(p) for p in self._discovered.values())
        self.count.setText(f"{len(hosts)} hosts · {total} paths · {disc} from robots/sitemap")

    def _discover(self):
        view = self.win.current_view() if hasattr(self.win, "current_view") else None
        url = view.url().toString() if view else ""
        host = urlparse(url).hostname or ""
        if not host or not url.startswith("http"):
            self.win.toast("Open the site you want to map first")
            return
        if not self._in_scope_host(host):
            QMessageBox.warning(self, "Out of scope",
                                f"{host} is not in the active engagement's scope. Add it to the scope to discover it.")
            return
        self.b_discover.setEnabled(False)
        self.b_discover.setText("Discovering…")
        from .security import discover
        px, verify = self.win.proxies(), self.win.verify_tls()
        self.win.runner.run(lambda: discover.discover(url, px, verify),
                            lambda ok, r: self._discovered_done(host, ok, r))

    def _discovered_done(self, host, ok, r):
        self.b_discover.setEnabled(True)
        self.b_discover.setText("Discover current site")
        if not ok:
            self.win.toast(f"Discovery failed: {r}")
            return
        n = 0
        for src_label, urls in (("robots.txt", r.get("robots", [])), ("sitemap.xml", r.get("sitemap", []))):
            for u in urls:
                p = urlparse(u)
                if not p.hostname:
                    continue
                bucket = self._discovered.setdefault(p.hostname, {})
                path = p.path or "/"
                if path not in bucket:
                    bucket[path] = {"url": u, "source": src_label}
                    n += 1
        self._build()
        self.win.toast(f"Discovered {n} new URL(s) from robots.txt / sitemap.xml"
                       + ("" if r.get("robots_ok") else " (no robots.txt)"))

    def _export(self):
        rows = self.win.security.traffic.model.rows if hasattr(self.win, "security") else []
        urls = {r["url"] for r in rows}
        for paths in self._discovered.values():
            urls.update(e["url"] for e in paths.values())
        if not urls:
            self.win.toast("Nothing to export yet — browse the site or run Discover")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export discovered URLs", "sitemap-urls.txt",
                                              "Text files (*.txt);;All files (*)")
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(sorted(urls)))
            self.win.toast(f"Exported {len(urls)} URL(s)")
        except OSError as e:
            QMessageBox.warning(self, "Export", f"Could not write file: {e}")

    def _open(self, it, _col):
        url = it.data(0, Qt.ItemDataRole.UserRole)
        if url:
            self.win.open_url(url, new_tab=True)


class _SortItem(QTreeWidgetItem):
    """Tree item that sorts numeric columns numerically (for the Intruder results table)."""

    def __lt__(self, other):
        col = self.treeWidget().sortColumn() if self.treeWidget() else 0
        a, b = self.text(col), other.text(col)
        try:
            return float(a) < float(b)
        except ValueError:
            return a < b


def _pane(title, widget, extra=None):
    """Labelled editor section used in stacked splitters (Repeater, Intruder, …). Consistent rhythm:
    12px above every section label, 6px between the label and its editor."""
    box = QWidget()
    bl = QVBoxLayout(box)
    bl.setContentsMargins(0, 12, 0, 0)
    bl.setSpacing(6)
    head = QHBoxLayout()
    lab = QLabel(title)
    lab.setObjectName("PaneLabel")
    head.addWidget(lab)
    head.addStretch(1)
    if extra:
        extra(head)
    bl.addLayout(head)
    bl.addWidget(widget, 1)
    return box


STATUS_COLOR = {2: "#1e8e3e", 3: "#4589ff", 4: "#fa7b17", 5: "#da1e28"}


# =================================================================== Intruder (fuzzer.py frontend)
class IntruderTab(QWidget):
    """Frontend for the throttled, scope-gated fuzzer backend. Does NOT implement its own engine —
    every request goes through fuzzer.run(), which enforces in-scope-only, a max rate and a budget."""
    result = Signal(dict)

    def __init__(self, win):
        super().__init__()
        self.win = win
        self._stop = False
        self._running = False
        self._results: list[dict] = []
        self._n = 0
        v = QVBoxLayout(self)
        intro = QLabel("Responsible <b>Intruder</b>: mark payload positions with <b>§</b>…<b>§</b> in the URL, "
                       "headers or body. One payload per line is substituted at every mark. The backend enforces "
                       "<b>in-scope-only</b> targets, a maximum request rate, and a hard request budget — there is "
                       "no unthrottled / credential-stuffing / brute-force mode.")
        intro.setWordWrap(True)
        intro.setObjectName("Muted")
        v.addWidget(intro)
        self.scope_lbl = QLabel("")
        self.scope_lbl.setObjectName("Muted")
        self.scope_lbl.setWordWrap(True)
        v.addWidget(self.scope_lbl)

        row = QHBoxLayout()
        self.method = QComboBox()
        self.method.addItems(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"])
        self.method.setEditable(True)
        row.addWidget(self.method)
        self.url = mono(QLineEdit())
        self.url.setPlaceholderText("https://target/search?q=§FUZZ§")
        self.url.textChanged.connect(self._update_positions)
        row.addWidget(self.url, 1)
        v.addLayout(row)

        split = QSplitter(Qt.Orientation.Vertical)
        self.headers = mono(QPlainTextEdit())
        self.headers.setPlaceholderText("Header: value (one per line) — may contain §marks§")
        self.headers.textChanged.connect(self._update_positions)
        self.body = mono(QPlainTextEdit())
        self.body.setPlaceholderText("Request body — may contain §marks§")
        self.body.textChanged.connect(self._update_positions)
        self.payloads = mono(QPlainTextEdit())
        self.payloads.setPlaceholderText("One payload per line")
        self.payloads.textChanged.connect(self._update_budget)
        split.addWidget(_pane("Request headers", self.headers))
        split.addWidget(_pane("Request body", self.body))

        def payload_tools(head):
            b = QPushButton("Load from file…")
            b.setObjectName("Segment")
            b.setFixedHeight(24)
            b.clicked.connect(self._load_payloads)
            head.addWidget(b)
        split.addWidget(_pane("Payloads (one per line)", self.payloads, payload_tools))
        split.setSizes([110, 90, 150])
        v.addWidget(split, 1)

        cfg = QHBoxLayout()
        cfg.setSpacing(8)
        cfg.addWidget(QLabel("Rate"))
        self.rate = QDoubleSpinBox()
        self.rate.setRange(0.2, fuzzer.MAX_RATE)
        self.rate.setSingleStep(0.5)
        self.rate.setValue(5.0)
        self.rate.setSuffix(" req/s")
        self.rate.setFixedWidth(120)
        cfg.addWidget(self.rate)
        cfg.addSpacing(16)
        cfg.addWidget(QLabel("Max requests"))
        self.maxreq = QSpinBox()
        self.maxreq.setRange(1, fuzzer.MAX_REQUESTS_CEILING)
        self.maxreq.setValue(200)
        self.maxreq.setFixedWidth(96)
        self.maxreq.valueChanged.connect(self._update_budget)
        cfg.addWidget(self.maxreq)
        cfg.addStretch(1)
        v.addLayout(cfg)
        # one tidy status line instead of two cramped labels on the control row
        self.status_line = QLabel("")
        self.status_line.setObjectName("Muted")
        v.addWidget(self.status_line)

        runrow = QHBoxLayout()
        self.b_start = QPushButton("Start attack")
        self.b_start.setObjectName("Primary")
        self.b_start.clicked.connect(self._start)
        self.b_stop = QPushButton("Stop")
        self.b_stop.setEnabled(False)
        self.b_stop.clicked.connect(self._stop_now)
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        runrow.addWidget(self.b_start)
        runrow.addWidget(self.b_stop)
        runrow.addWidget(self.progress, 1)
        v.addLayout(runrow)

        fr = QHBoxLayout()
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter results: status / payload / location…")
        self.filter.textChanged.connect(self._apply_filter)
        fr.addWidget(self.filter, 1)
        v.addLayout(fr)
        self.table = QTreeWidget()
        self.table.setHeaderLabels(["#", "Payload", "Status", "Length", "Time (ms)", "Location / Error"])
        self.table.setRootIsDecorated(False)
        self.table.setSortingEnabled(True)
        self.table.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._menu)
        self.table.itemDoubleClicked.connect(lambda *_: self._to_repeater())
        v.addWidget(self.table, 1)
        self.summary = QLabel("")
        self.summary.setObjectName("Muted")
        v.addWidget(self.summary)

        self.result.connect(self._on_result)
        self._update_positions()
        self._update_budget()

    def showEvent(self, e):
        super().showEvent(e)
        self._refresh_scope()

    # ---------------------------------------------------------- helpers
    def _refresh_scope(self):
        eng = self.win.engagement
        if eng and eng.scope:
            self.scope_lbl.setText(f"Authorized scope — <b>{escape(eng.name)}</b>: {escape(', '.join(eng.scope))}")
        elif eng:
            self.scope_lbl.setText(f"Engagement <b>{escape(eng.name)}</b> has no scope set. Add a target scope "
                                   "(toolbar → engagement) before testing.")
        else:
            self.scope_lbl.setText("No engagement selected. Active testing requires an authorized engagement with "
                                   "a target scope (toolbar, left of the address bar).")

    def _templates(self):
        return self.url.text(), self.headers.toPlainText(), self.body.toPlainText()

    def _update_positions(self):
        n = sum(fuzzer.positions(t) for t in self._templates())
        self._update_status()
        return n

    def _payload_lines(self):
        return [ln for ln in self.payloads.toPlainText().splitlines() if ln.strip() != ""]

    def _update_budget(self):
        self._update_status()

    def _update_status(self):
        n_pos = sum(fuzzer.positions(t) for t in self._templates())
        n_pay = len(self._payload_lines())
        eff = min(n_pay, self.maxreq.value(), fuzzer.MAX_REQUESTS_CEILING)
        cap = " · budget-capped" if eff < n_pay else ""
        self.status_line.setText(
            f"{n_pos} payload position{'' if n_pos == 1 else 's'} · "
            f"will send <b>{eff}</b> of {n_pay} payload{'' if n_pay == 1 else 's'}{cap}")

    def _load_payloads(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load payload list", "", "Text files (*.txt);;All files (*)")
        if path:
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    self.payloads.setPlainText(fh.read())
            except OSError as e:
                QMessageBox.warning(self, "Payloads", f"Could not read file: {e}")

    # ---------------------------------------------------------- run / stop
    def _start(self):
        if self._running:
            return
        url = self.url.text().strip()
        host = urlparse(url).hostname or ""
        if not host:
            QMessageBox.information(self, "Intruder", "Enter a target URL first.")
            return
        if self._update_positions() == 0:
            QMessageBox.information(self, "Intruder", "Add at least one payload position: wrap it in §marks§, "
                                                      "e.g. https://target/search?q=§FUZZ§")
            return
        payloads = self._payload_lines()
        if not payloads:
            QMessageBox.information(self, "Intruder", "Add at least one payload (one per line).")
            return
        eng = self.win.engagement
        if not eng or not eng.scope:
            QMessageBox.warning(self, "Authorization required",
                                "Active testing requires an engagement with a target scope. Create or select one "
                                "(toolbar) and add the target to its scope before running the Intruder.")
            return
        in_scope = lambda h: bool(eng.in_scope(h))  # noqa: E731
        if not in_scope(host):
            QMessageBox.warning(self, "Out of scope",
                                f"{host} is not in the scope of engagement '{eng.name}'. The Intruder only tests "
                                "in-scope hosts. Add it to the engagement scope if you are authorized to test it.")
            return
        eff = min(len(payloads), self.maxreq.value())
        ok = QMessageBox.question(
            self, "Confirm authorized test",
            f"Send up to <b>{eff}</b> requests to <b>{escape(host)}</b> at {self.rate.value():.1f} req/s?\n\n"
            "Only test systems you are explicitly authorized to test.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
        if ok != QMessageBox.StandardButton.Yes:
            return

        self._stop = False
        self._running = True
        self._results = []
        self._n = 0
        self.table.setSortingEnabled(False)
        self.table.clear()
        self.b_start.setEnabled(False)
        self.b_stop.setEnabled(True)
        self.progress.setRange(0, eff)
        self.progress.setValue(0)
        self.summary.setText("Running…")
        method, (u, h, b) = self.method.currentText(), self._templates()
        rate, maxreq = self.rate.value(), self.maxreq.value()
        px, verify = self.win.proxies(), self.win.verify_tls()

        def worker():
            return fuzzer.run(method, u, h, b, payloads, in_scope=in_scope, rate_per_sec=rate,
                              max_requests=maxreq, proxies=px, verify=verify,
                              on_result=lambda r: self.result.emit(r), should_stop=lambda: self._stop)

        def finished(okk, res):
            self._running = False
            self.b_start.setEnabled(True)
            self.b_stop.setEnabled(False)
            self.table.setSortingEnabled(True)
            if okk:
                self.summary.setText(f"Done — sent {res.get('sent', 0)} request(s)"
                                     + (" · budget reached" if res.get("capped") else "")
                                     + (" · stopped" if self._stop else ""))
            else:
                self.summary.setText(f"Failed: {res}")
                QMessageBox.warning(self, "Intruder", f"Attack failed:\n{res}")
        self.win.runner.run(worker, finished)

    def _stop_now(self):
        self._stop = True
        self.b_stop.setEnabled(False)
        self.summary.setText("Stopping after the current request…")

    def _on_result(self, r):
        self._results.append(r)
        self._n += 1
        self.progress.setValue(self._n)
        status = r.get("status")
        row = _SortItem([str(self._n), r.get("payload", ""), str(status) if status is not None else "ERR",
                         str(r.get("length", 0)), str(r.get("ms", 0)),
                         r.get("location") or r.get("error") or ""])
        if status:
            row.setForeground(2, QBrush(QColor(STATUS_COLOR.get(status // 100, "#8d8d8d"))))
        else:
            row.setForeground(2, QBrush(QColor("#8d8d8d")))
        row.setData(0, Qt.ItemDataRole.UserRole, r)
        self.table.addTopLevelItem(row)
        self._filter_row(row)
        self.summary.setText(f"{self._n} sent")

    def _apply_filter(self):
        for i in range(self.table.topLevelItemCount()):
            self._filter_row(self.table.topLevelItem(i))

    def _filter_row(self, row):
        f = self.filter.text().lower().strip()
        hay = " ".join(row.text(c) for c in range(row.columnCount())).lower()
        row.setHidden(bool(f) and f not in hay)

    def _current(self):
        it = self.table.currentItem()
        return it.data(0, Qt.ItemDataRole.UserRole) if it else None

    def _concrete(self, r):
        p = r.get("payload", "")
        u, h, b = self._templates()
        return (fuzzer.apply_payload(u, p), fuzzer.apply_payload(h, p), fuzzer.apply_payload(b, p))

    def _to_repeater(self):
        r = self._current()
        if not r:
            return
        u, h, _b = self._concrete(r)
        self.win.security.tools_tab.load_request(self.method.currentText(), u, tools.parse_headers(h))
        self.win.security.show_tab("Tools")

    def _menu(self, pos):
        it = self.table.itemAt(pos)
        if not it:
            return
        r = it.data(0, Qt.ItemDataRole.UserRole)
        m = QMenu(self)
        m.addAction("Send to Repeater", self._to_repeater)
        m.addAction("Add as finding…", lambda: self._add_finding(r))
        m.addAction("Copy payload", lambda: QGuiApplication.clipboard().setText(r.get("payload", "")))
        m.exec(self.table.viewport().mapToGlobal(pos))

    def _add_finding(self, r):
        u, h, b = self._concrete(r)
        evidence = (f"Request: {self.method.currentText()} {u}\n{h}\n\n{b}\n\n"
                    f"Response: status={r.get('status')} length={r.get('length')} time={r.get('ms')}ms "
                    f"{r.get('location') or r.get('error') or ''}").strip()
        self.win.add_finding_dialog(title=f"Intruder result: payload {r.get('payload','')[:40]}",
                                    severity="info", url=u, description="Captured during authorized Intruder testing.",
                                    evidence=evidence)


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
        self.busy = BusyOverlay(self.tree)
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
        self.counts.setText(f"{c['sinks']} sinks · {c['sources']} sources · {c['flows']} potential flows "
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
            it = QTreeWidgetItem([i["title"], i["severity"]])
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


class SecurityPanel(QDockWidget):
    """Grouped vertical navigation (Protection / Website Intelligence / Traffic / Testing / Findings)
    over a stacked content area — reuses every existing tab widget, no horizontal tab overflow."""

    def __init__(self, win):
        super().__init__("Security", win)
        self.setObjectName("SecurityPanel")
        self.setMinimumWidth(360)
        self.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetMovable
                         | QDockWidget.DockWidgetFeature.DockWidgetFloatable
                         | QDockWidget.DockWidgetFeature.DockWidgetClosable)
        self.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)
        self.overview = OverviewTab(win)
        self.traffic = TrafficTab(win)
        self.sitemap = SiteMapTab(win)
        self.recon = ReconTab(win)
        self.tools_tab = ToolsTab(win)
        self.findings = FindingsTab(win)
        self.shields = ShieldsTab(win)
        self.intruder = IntruderTab(win)
        self.dom = DomTab(win)
        groups = [
            ("PROTECTION", [("Shields", self.shields)]),
            ("INTELLIGENCE", [("Overview", self.overview), ("Site map", self.sitemap), ("Recon", self.recon)]),
            ("TRAFFIC", [("Traffic", self.traffic)]),
            ("TESTING", [("Intruder", self.intruder), ("DOM Analysis", self.dom), ("Tools", self.tools_tab)]),
            ("FINDINGS", [("Findings", self.findings)]),
        ]
        root = QWidget()
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        # left nav: section captions + nav buttons in a real scroll area (independent of the fixed header);
        # avoids the QListWidget::item padding/selection quirks that clipped the section headings.
        self.nav = QScrollArea(objectName="PanelNav")
        self.nav.setWidgetResizable(True)
        self.nav.setFixedWidth(150)
        self.nav.setFrameShape(self.nav.Shape.NoFrame)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        navbody = QWidget(objectName="NavBody")
        nb = QVBoxLayout(navbody)
        nb.setContentsMargins(0, 18, 0, 12)  # breathing room between the fixed header and the first caption
        nb.setSpacing(2)
        self.stack = QStackedWidget()
        self._nav_buttons: dict[str, tuple] = {}   # name -> (button, stack index)
        for gi, (title, items) in enumerate(groups):
            cap = QLabel(title, objectName="NavGroup")
            cap.setContentsMargins(16, 16 if gi else 10, 12, 4)  # space above each group (header gap handled by NavBody margin)
            nb.addWidget(cap)
            for name, widget in items:
                btn = QPushButton(name, objectName="NavItem")
                btn.setCheckable(True)
                btn.setAutoExclusive(True)
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                page = QScrollArea()  # tall pages scroll instead of squashing; width follows the panel
                page.setWidgetResizable(True)
                page.setFrameShape(QScrollArea.Shape.NoFrame)
                page.setWidget(widget)
                idx = self.stack.addWidget(page)
                btn.clicked.connect(lambda _c=False, n=name: self._select(n))
                self._nav_buttons[name] = (btn, idx)
                nb.addWidget(btn)
        nb.addStretch(1)
        self.nav.setWidget(navbody)
        # one consistent outer margin + row spacing for every panel page (alignment & rhythm across tabs)
        for _n, (_b, idx) in self._nav_buttons.items():
            lay = self.stack.widget(idx).widget().layout()
            if lay is not None:
                lay.setContentsMargins(16, 14, 16, 12)
                lay.setSpacing(10)
        from .widgets import make_rows_wrap
        make_rows_wrap(self.stack)  # button / filter rows wrap instead of forcing pages wider than the panel
        for lab in self.stack.findChildren(QLabel):  # long explanatory labels wrap with the panel width
            if not lab.wordWrap() and len(lab.text()) > 40:
                lab.setWordWrap(True)
        h.addWidget(self.nav)
        h.addWidget(self.stack, 1)
        self.setWidget(root)
        self.show_tab("Shields")

    def current_page(self):
        """The visible tab widget (pages are wrapped in scroll areas)."""
        w = self.stack.currentWidget()
        return w.widget() if isinstance(w, QScrollArea) else w

    def _select(self, name):
        btn, idx = self._nav_buttons[name]
        btn.setChecked(True)
        self.stack.setCurrentIndex(idx)
        self._fade(self.stack.currentWidget())

    def show_tab(self, name):
        self.show()
        if name in self._nav_buttons:
            self._select(name)

    def _fade(self, w):
        from PySide6.QtCore import QEasingCurve, QPropertyAnimation
        from PySide6.QtWidgets import QGraphicsOpacityEffect
        if not w:
            return
        eff = QGraphicsOpacityEffect(w)
        w.setGraphicsEffect(eff)
        anim = QPropertyAnimation(eff, b"opacity", self)
        anim.setDuration(150)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.finished.connect(lambda: w.setGraphicsEffect(None))
        self._nav_anim = anim
        anim.start()
