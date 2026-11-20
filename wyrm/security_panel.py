"""Security panel: Overview (passive checks) · Traffic · Recon · Tools · Findings."""
from __future__ import annotations

import json
from datetime import datetime
from html import escape
from pathlib import Path
from urllib.parse import urlparse

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt, QTimer
from PySide6.QtGui import QAction, QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView, QCheckBox, QComboBox, QDockWidget, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMenu, QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTableView, QTabWidget,
    QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from . import theme
from .dialogs import FindingDialog
from .linkguard import registered_domain
from .security import analyzer, intel, report, tools

SEV_COLOR = theme.SEVERITY
PAGEINFO_JS = (Path(__file__).parent / "security" / "pageinfo.js").read_text(encoding="utf-8")


def mono(widget):
    f = widget.font()
    f.setFamilies([theme.MONO, "Consolas", "monospace"])
    widget.setFont(f)
    return widget


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
        v.addWidget(self.list, 1)
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
        self.win.runner.run(fn, lambda ok, r: render(d, r) if ok else self.status.setText(f"{label} failed: {r}"), d)

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


# =================================================================== Tools
class ToolsTab(QTabWidget):
    def __init__(self, win):
        super().__init__()
        self.win = win
        self._confirmed_hosts: set[str] = set()  # out-of-scope hosts the user already OK'd in the Repeater
        self.addTab(self._decoder(), "Decoder")
        self.addTab(self._jwt(), "JWT")
        self.addTab(self._hash(), "Hash")
        self.addTab(self._repeater(), "Repeater")
        self.addTab(self._rewrite(), "Match & Replace")

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
        split = QSplitter(Qt.Orientation.Vertical)
        self.r_headers = mono(QPlainTextEdit())
        self.r_headers.setPlaceholderText("Header: value (one per line)")
        self.r_body = mono(QPlainTextEdit())
        self.r_body.setPlaceholderText("Request body")
        self.r_resp = mono(QPlainTextEdit())
        self.r_resp.setReadOnly(True)
        self.r_resp.setPlaceholderText("Response appears here")
        for x in (self.r_headers, self.r_body, self.r_resp):
            split.addWidget(x)
        split.setSizes([90, 70, 300])
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
        return w

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
        self.setCurrentIndex(3)
        self.r_method.setCurrentText(method or "GET")
        self.r_url.setText(url)
        self.r_headers.setPlainText("\n".join(f"{k}: {v}" for k, v in headers.items()))

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
        self.r_resp.setPlainText("Sending…")
        args = (self.r_method.currentText(), url, self.r_headers.toPlainText(), self.r_body.toPlainText(),
                self.win.proxies(), self.win.verify_tls(), self.r_follow.isChecked())

        def done(ok, r):
            self.r_send.setEnabled(True)
            self.r_resp.setPlainText(f"{r['head']}\n\n{r['body']}" if ok else f"Error: {r}")
        self.win.runner.run(lambda: tools.send_request(*args), done)


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
    TOGGLES = [("ads", "Block ads"), ("antifp", "Resist fingerprinting (canvas/WebGL/audio noise — applies to new tabs)"),
               ("trackers", "Block trackers (lists + HackPi beacon heuristics)"),
               ("malware", "Block malware and phishing sites"), ("linkguard", "Smart link check (phishing heuristics)"),
               ("popups", "Block ad pop-ups"), ("params", "Remove tracking parameters from links"),
               ("youtube", "Remove YouTube ads (applies to new tabs)")]

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
        self.checks = {}
        for key, label in self.TOGGLES:
            c = QCheckBox(label)
            c.setChecked(win.shields.enabled(key))
            c.toggled.connect(lambda on, k=key: (win.shields.set_enabled(k, on), self._reload_hint()))
            v.addWidget(c)
            self.checks[key] = c

        v.addWidget(QLabel("<b>Encryption</b>"))
        self.https = QCheckBox("HTTPS-Only mode: upgrade every connection to HTTPS")
        self.https.setChecked(win.https_only())
        self.https.toggled.connect(lambda on: win.settings.setValue("privacy/https_only", on))
        v.addWidget(self.https)
        row = QHBoxLayout()
        row.addWidget(QLabel("Encrypted DNS"))
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
        foot.addWidget(upd)
        v.addLayout(foot)
        if win.tor:
            trow = QHBoxLayout()
            self.tor_label = QLabel("")
            self.tor_label.setWordWrap(True)
            trow.addWidget(self.tor_label, 1)
            nb = QPushButton("New identity")
            nb.clicked.connect(win.tor_new_identity)
            trow.addWidget(nb)
            v.addLayout(trow)
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
        rows = "".join("<tr>" + "".join(cells[i:i + 4]) + "</tr>" for i in range(0, len(cells), 4))
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
        self.lists.setText(f"Filter rules: {r} · updated {self.win.shields.last_updated()}. Engine: Brave adblock-rust.")
        if self.win.tor and hasattr(self, "tor_label"):
            self.tor_label.setText(f"<b>Tor circuit:</b> {escape(self.win.tor.circuit_summary())}")

    def showEvent(self, e):
        super().showEvent(e)
        self.refresh()


# =================================================================== dock
class SecurityPanel(QDockWidget):
    def __init__(self, win):
        super().__init__("Security", win)
        self.setObjectName("SecurityPanel")
        self.setMinimumWidth(420)
        self.tabs = QTabWidget()
        self.overview = OverviewTab(win)
        self.traffic = TrafficTab(win)
        self.recon = ReconTab(win)
        self.tools_tab = ToolsTab(win)
        self.findings = FindingsTab(win)
        self.shields = ShieldsTab(win)
        for w, name in ((self.shields, "Shields"), (self.overview, "Overview"), (self.traffic, "Traffic"),
                        (self.recon, "Recon"), (self.tools_tab, "Tools"), (self.findings, "Findings")):
            self.tabs.addTab(w, name)
        self.setWidget(self.tabs)
        self.tabs.currentChanged.connect(self._fade_tab)

    def _fade_tab(self, idx):
        """Quick fade-in of the newly selected tab (animation when switching panels)."""
        from PySide6.QtCore import QEasingCurve, QPropertyAnimation
        from PySide6.QtWidgets import QGraphicsOpacityEffect
        w = self.tabs.widget(idx)
        if not w:
            return
        eff = QGraphicsOpacityEffect(w)
        w.setGraphicsEffect(eff)
        anim = QPropertyAnimation(eff, b"opacity", self)
        anim.setDuration(160)
        anim.setStartValue(0.0)
        anim.setEndValue(1.0)
        anim.setEasingCurve(QEasingCurve.Type.OutCubic)
        anim.finished.connect(lambda: w.setGraphicsEffect(None))  # remove effect so repaints stay cheap
        self._tab_anim = anim  # keep a ref so it isn't GC'd
        anim.start()

    def show_tab(self, name):
        self.show()
        for i in range(self.tabs.count()):
            if self.tabs.tabText(i) == name:
                self.tabs.setCurrentIndex(i)
