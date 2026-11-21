#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/scanner.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Developer: @kwan (Scanner: port scan, CORS and clickjacking tests)
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Security panel → Scanner: port scan (nmap or built-in), CORS misconfiguration test, clickjacking test, and
the ProjectDiscovery tools installed on this machine (subfinder, httpx, katana, nuclei, naabu, dnsx, …).

Active checks (port scan, CORS, and any ProjectDiscovery tool that contacts the target) only run on hosts
inside the current engagement's scope. The clickjacking check is a single ordinary page request, so it works
on any page you are viewing.
"""
from __future__ import annotations

from html import escape
from urllib.parse import quote, urlparse

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton, QSplitter,
    QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from .common import SEV_COLOR, sev_badge
from ..security import pdtools, portscan, webchecks
from ..widgets import BusyOverlay


class ScannerTab(QWidget):
    _pd_line = Signal(str, object)   # one streamed line from a ProjectDiscovery tool (worker -> UI thread)
    _pd_done = Signal(bool, object)

    def __init__(self, win):
        super().__init__()
        self.win = win
        self._pd_running = False
        self._pd_line.connect(self._on_pd_line)
        self._pd_done.connect(self._on_pd_done)
        v = QVBoxLayout(self)
        intro = QLabel("<b>Scanner</b> — for targets you are <b>authorized</b> to test. Port scan and CORS test only "
                       "run on hosts in your engagement scope; the clickjacking check works on any page you open.")
        intro.setObjectName("Muted")
        intro.setWordWrap(True)
        v.addWidget(intro)

        row = QHBoxLayout()
        row.addWidget(QLabel("Target"))
        self.target = QLineEdit()
        self.target.setPlaceholderText("https://app.example.com/  or  host / IP")
        row.addWidget(self.target, 1)
        use = QPushButton("Use current")
        use.clicked.connect(self.use_current)
        row.addWidget(use)
        v.addLayout(row)

        # nmap options appear only when nmap is installed; otherwise the built-in scanner is used silently
        has_nmap = bool(portscan.nmap_path())
        self.use_nmap = QCheckBox("Use nmap")
        self.use_nmap.setChecked(has_nmap)
        self.versions = QCheckBox("Service versions (-sV)")
        self.versions.setToolTip("nmap: identify the software behind each open port (slower)")
        if has_nmap:
            opts = QHBoxLayout()
            opts.addWidget(self.use_nmap)
            opts.addWidget(self.versions)
            opts.addStretch(1)
            v.addLayout(opts)

        btns = QHBoxLayout()
        for label, fn, tip in (
                ("Port scan", self.port_scan, "Top 100 TCP ports (TCP connect, polite timing)"),
                ("CORS test", self.cors, "Crafted Origin headers — after Chen et al., USENIX Security 2018"),
                ("Clickjacking test", self.clickjacking, "Frame protection — after Huang et al., USENIX Security 2012"),
                ("Framing proof-of-concept", self.frame_poc, "Open a local page that frames the target")):
            b = QPushButton(label)
            b.setToolTip(tip)
            b.clicked.connect(fn)
            btns.addWidget(b)
        btns.addStretch(1)
        v.addLayout(btns)

        # ProjectDiscovery tools — only the ones installed on this machine are offered (like nmap)
        self._pd_tools = pdtools.installed()
        if self._pd_tools:
            pd = QHBoxLayout()
            pd.addWidget(QLabel("ProjectDiscovery"))
            self.pd_box = QComboBox()
            for t in self._pd_tools:
                self.pd_box.addItem(f"{t.name} — {t.desc}", t.key)
            self.pd_box.setToolTip("Open-source ProjectDiscovery tools detected on this computer")
            pd.addWidget(self.pd_box, 1)
            self.pd_run = QPushButton("Run")
            self.pd_run.setObjectName("Primary")
            self.pd_run.clicked.connect(self.run_pd)
            pd.addWidget(self.pd_run)
            self.pd_stop = QPushButton("Stop")
            self.pd_stop.clicked.connect(self._stop_pd)
            self.pd_stop.setEnabled(False)
            pd.addWidget(self.pd_stop)
            v.addLayout(pd)

        split = QSplitter(Qt.Orientation.Vertical)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Result", "Severity"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.tree.currentItemChanged.connect(self._show)
        self.tree.itemDoubleClicked.connect(lambda it, _c: QGuiApplication.clipboard().setText(it.text(0)))
        split.addWidget(self.tree)
        self.busy = BusyOverlay(self.tree)
        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        split.addWidget(self.detail)
        split.setSizes([300, 160])
        v.addWidget(split, 1)
        foot = QHBoxLayout()
        self.status = QLabel("")
        self.status.setObjectName("Muted")
        self.status.setWordWrap(True)
        foot.addWidget(self.status, 1)
        add = QPushButton("Add to findings")
        add.clicked.connect(self._add_finding)
        foot.addWidget(add)
        v.addLayout(foot)

    # ---------------------------------------------------------------- target + authorization
    def use_current(self):
        view = self.win.current_view()
        url = view.url().toString() if view else ""
        if url.startswith(("http://", "https://")):
            self.target.setText(url)

    def _url(self) -> str:
        t = self.target.text().strip()
        if not t:
            self.use_current()
            t = self.target.text().strip()
        if t and "://" not in t:
            t = "https://" + t
        return t

    def _host(self) -> str:
        return (urlparse(self._url()).hostname or "").lower()

    def _authorized(self, host: str, what: str) -> bool:
        eng = self.win.engagement
        if not host:
            self.status.setText("Enter a target or open a page first.")
            return False
        if not eng or not eng.scope or eng.in_scope(host) is not True:
            QMessageBox.information(
                self, "Authorized targets only",
                f"{what} only runs on hosts in your engagement scope.\n\n"
                f"Select or create an engagement (dropdown left of the address bar) that includes {host}, "
                "and only test systems you own or have written permission to test.")
            return False
        return True

    # ---------------------------------------------------------------- checks
    def _run(self, label, fn, render):
        self.busy.start(f"{label}…")
        self.status.setText(f"{label}…")

        def done(ok, res):
            self.busy.stop()
            if ok:
                render(res)
            else:
                self.status.setText(f"{label} failed: {res}")
        self.win.runner.run(fn, done)

    def _add(self, text, sev, detail_html, data=None):
        it = QTreeWidgetItem([text, sev.upper() if sev else ""])
        it.setData(0, Qt.ItemDataRole.UserRole, {"title": text, "severity": sev or "info", "detail": detail_html,
                                                 **(data or {})})
        if sev in SEV_COLOR:
            it.setForeground(1, QBrush(QColor(SEV_COLOR[sev])))
        self.tree.addTopLevelItem(it)
        return it

    def port_scan(self):
        host = self._host()
        if not self._authorized(host, "Port scanning"):
            return
        nmap, versions = self.use_nmap.isChecked(), self.versions.isChecked()

        def render(r):
            self.tree.clear()
            for p in r["open"]:
                sev = "medium" if p["risky"] else "info"
                note = " — exposed database/admin service: should it be reachable?" if p["risky"] else ""
                self._add(f"{p['port']}/tcp open  {p['service']}" + (f"  ({p['product']})" if p["product"] else ""),
                          sev, f"<b>{p['port']}/tcp</b> {escape(p['service'])} {escape(p['product'])}{escape(note)}",
                          {"url": f"{host}:{p['port']}"})
            self.status.setText(f"{len(r['open'])} open port(s) on {host} ({r['ip']}) — {r['engine']}, top 100 TCP.")
        self._run(f"Scanning {host}", lambda: portscan.scan(host, nmap, versions), render)

    def cors(self):
        url, host = self._url(), self._host()
        if not self._authorized(host, "The CORS test"):
            return
        px, verify = self.win.proxies(), self.win.verify_tls()

        def render(r):
            self.tree.clear()
            for f in r["findings"]:
                self._add(f"CORS: {f['title']}", f["severity"],
                          f"{sev_badge(f['severity'])} <b>{escape(f['title'])}</b><br>Origin sent: <code>"
                          f"{escape(f['origin'])}</code><br>Access-Control-Allow-Origin: <code>{escape(f['acao'])}"
                          f"</code><br>Credentials allowed: <b>{'yes' if f['credentials'] else 'no'}</b><br><br>"
                          f"{escape(f['detail'])}<br><br><i>Method: {escape(r['paper'])}</i>", {"url": url})
            if not r["findings"]:
                self._add("CORS: no untrusted origin was accepted", "info",
                          f"All {len(r['checked'])} crafted origins were rejected.<br><i>{escape(r['paper'])}</i>")
            self.status.setText(f"CORS test on {url}: {len(r['findings'])} issue(s), {len(r['checked'])} requests.")
        self._run("CORS test", lambda: webchecks.cors_test(url, px, verify), render)

    # ---------------------------------------------------------------- ProjectDiscovery tools (streamed)
    def run_pd(self):
        if self._pd_running:
            return
        tool = pdtools.TOOLS_BY_KEY[self.pd_box.currentData()]
        target = {"domain": self._host(), "host": self._host(), "url": self._url(),
                  "cidr": self.target.text().strip(), "asn": self.target.text().strip()}[tool.takes]
        if not target:
            self.status.setText("Enter a target first.")
            return
        if tool.active and not self._authorized(self._host(), f"{tool.name}"):
            return
        self.tree.clear()
        self._pd_running = True
        self.pd_run.setEnabled(False)
        self.pd_stop.setEnabled(True)
        self.busy.start(f"{tool.name} running…")
        self.status.setText(f"{tool.name} {target} …")
        self._pd_count = 0
        self._pd_stop_flag = False
        px = self.win.proxies()

        def work():
            return pdtools.run(tool, target, lambda text, obj: self._pd_line.emit(text, obj), proxies=px,
                               should_stop=lambda: self._pd_stop_flag)
        self.win.runner.run(work, lambda ok, res: self._pd_done.emit(bool(ok), res))

    def _on_pd_line(self, text, obj):
        self._pd_count = getattr(self, "_pd_count", 0) + 1
        sev = (obj or {}).get("info", {}).get("severity", "") if isinstance(obj, dict) else ""
        sev = sev if sev in SEV_COLOR else ""
        it = self._add(text, sev, f"<pre style='white-space:pre-wrap'>{escape(text)}</pre>",
                       {"raw": obj, "url": text if text.startswith("http") else ""})
        if self._pd_count <= 1:
            self.tree.setCurrentItem(it)

    def _on_pd_done(self, ok, res):
        self._pd_running = False
        self.busy.stop()
        if hasattr(self, "pd_run"):
            self.pd_run.setEnabled(True)
            self.pd_stop.setEnabled(False)
        n = getattr(self, "_pd_count", 0)
        if not ok:
            self.status.setText(f"Tool failed: {res}")
        else:
            extra = f" ({res['stopped']})" if isinstance(res, dict) and res.get("stopped") else ""
            self.status.setText(f"{n} result(s){extra}.")

    def _stop_pd(self):
        self._pd_stop_flag = True   # the worker kills the subprocess at the next line; _on_pd_done resets the UI
        self.pd_stop.setEnabled(False)
        self.status.setText("Stopping…")

    def clickjacking(self):
        url = self._url()
        if not url:
            return
        px, verify = self.win.proxies(), self.win.verify_tls()

        def render(r):
            self.tree.clear()
            self._add(f"Clickjacking: {r['verdict']}", r["severity"],
                      f"{sev_badge(r['severity'])} {escape(r['verdict'])}<br><br>X-Frame-Options: <code>"
                      f"{escape(r['x_frame_options'] or '(none)')}</code><br>CSP frame-ancestors: <code>"
                      f"{escape(r['frame_ancestors'] or '(none)')}</code><br><br>Use <b>Framing proof-of-concept</b> "
                      f"to see it framed.<br><i>Method: {escape(r['paper'])}</i>", {"url": url})
            self.status.setText(f"Clickjacking check on {url}: HTTP {r['status']}.")
        self._run("Clickjacking test", lambda: webchecks.clickjacking_test(url, px, verify), render)

    def frame_poc(self):
        url = self._url()
        if url:
            self.win.open_url("wyrm://frametest?u=" + quote(url, safe=""), new_tab=True)

    # ---------------------------------------------------------------- details / findings
    def _show(self, it, _prev=None):
        d = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        self.detail.setHtml(d["detail"] if d else "")

    def _add_finding(self):
        it = self.tree.currentItem()
        d = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not d:
            self.status.setText("Select a result first.")
            return
        sev = d["severity"] if d["severity"] in ("critical", "high", "medium", "low", "info") else "info"
        self.win.add_finding_dialog(title=d["title"], severity=sev, url=d.get("url", ""),
                                    description=QTextBrowser(html=d["detail"]).toPlainText())
