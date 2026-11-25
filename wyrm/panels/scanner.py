#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/scanner.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Developer: Kwan (Scanner: port scan, CORS and clickjacking tests)
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Security panel → Scanner: port scan (nmap or built-in), CORS misconfiguration test, clickjacking test, and
the ProjectDiscovery tools installed on this machine (subfinder, httpx, katana, nuclei, naabu, dnsx, …).

Active checks (port scan, CORS, and any ProjectDiscovery tool that contacts the target) only run on hosts
inside the current engagement's scope. The clickjacking check is a single ordinary page request, so it works
on any page you are viewing.
"""
from __future__ import annotations

from html import escape
from html.parser import HTMLParser
from urllib.parse import quote, urlparse

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton, QSplitter,
    QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

from .common import SEV_COLOR, sev_badge
from ..security import jsrecon, pdtools, portscan, severity as _sev, techdetect, webchecks
from ..widgets import SkeletonOverlay


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def _js_plan(target: str, cur_url: str, in_scope: bool) -> str:
    """Decide how JS recon runs (QA-H3). 'dom' reads the live same-origin tab; 'fetch' downloads the target
    page; 'dom_inline' reads only the current tab's inline scripts (read-only, allowed out of scope); 'refuse'
    sends nothing. A network fetch ('fetch'/external scripts) is only ever chosen when the host is in scope."""
    same = bool(cur_url) and _same_origin(cur_url, target)
    if in_scope:
        return "dom" if same else "fetch"
    return "dom_inline" if same else "refuse"


class _ScriptExtract(HTMLParser):
    """Pull <script src> and inline script text out of a fetched HTML page."""
    def __init__(self):
        super().__init__()
        self.src: list[str] = []
        self.inline: list[str] = []
        self._in = False
        self._buf: list[str] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            d = dict(attrs)
            if d.get("src"):
                self.src.append(d["src"])
            else:
                self._in, self._buf = True, []

    def handle_data(self, data):
        if self._in:
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._in:
            self.inline.append("".join(self._buf))
            self._in = False


class ScannerTab(QWidget):
    _pd_line = Signal(str, object)   # one streamed line from a ProjectDiscovery tool (worker -> UI thread)
    _pd_done = Signal(bool, object)
    _pd_status = Signal(str)         # status text from the worker (e.g. the scheme it picked)
    _logo_ready = Signal(object, str)  # (tree item, local icon path) — technology logo fetched off-thread

    def __init__(self, win):
        super().__init__()
        self.win = win
        self._pd_running = False
        self._pd_line.connect(self._on_pd_line)
        self._pd_done.connect(self._on_pd_done)
        self._pd_status.connect(lambda t: self.status.setText(t))  # status label is created below
        self._logo_ready.connect(self._set_logo)
        v = QVBoxLayout(self)
        intro = QLabel("<b>Scanner</b> — for targets you are <b>authorized</b> to test. Port scan and CORS test only "
                       "run on hosts in your engagement scope; the clickjacking check works on any page you open.")
        intro.setObjectName("Muted")
        intro.setWordWrap(True)
        v.addWidget(intro)

        row = QHBoxLayout()
        row.addWidget(QLabel("Target"))
        self.target = QLineEdit()
        self.target.setPlaceholderText("example.com,  https://app.example.com/path,  host:8443,  IP  or  10.0.0.0/24")
        self.target.setToolTip("Type a domain, URL, host:port, IP, IP range (CIDR) or AS number. Wyrm gives each tool "
                               "what it needs: domain tools get the domain, URL tools get a URL (https:// if the "
                               "site supports it, else http://), and port-aware tools keep your port.")
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
                ("Technologies", self.technologies, "What the site is built with: CMS, frameworks, servers, analytics "
                 "(Wappalyzer-style, built in). One normal request, like opening the page."),
                ("JS recon", self.js_recon, "Pull endpoints, API paths and leaked secrets (API keys, tokens) "
                 "from the open page's scripts (LinkFinder / SecretFinder style)"),
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
        self._has_sev = False
        self.tree.setColumnHidden(1, True)   # the Severity column appears only when a tool actually reports one
        self.tree.currentItemChanged.connect(self._show)
        self.tree.itemDoubleClicked.connect(lambda it, _c: QGuiApplication.clipboard().setText(it.text(0)))
        split.addWidget(self.tree)
        self.busy = SkeletonOverlay(self.tree)
        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        self.detail.anchorClicked.connect(lambda u: self.win.open_url(u.toString(), new_tab=True))
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

    # extra severity aliases some tools emit, mapped onto the standard colour scheme
    _SEV_ALIAS = {"warning": "medium", "informational": "info", "critical": "critical", "high": "high",
                  "medium": "medium", "low": "low", "info": "info"}

    def _add(self, text, sev, detail_html, data=None):
        raw = (sev or "").lower()
        norm = self._SEV_ALIAS.get(raw)              # a recognised severity, or None for severity-less results
        color = SEV_COLOR.get(norm) if norm else None
        it = QTreeWidgetItem([text, _sev.title(norm) if norm else ""])
        it.setData(0, Qt.ItemDataRole.UserRole, {"title": text, "severity": norm or "info", "detail": detail_html,
                                                 **(data or {})})
        if color:                                    # colour the severity text in its own style, and reveal the column
            it.setForeground(1, QBrush(QColor(color)))
            f = it.font(1)
            f.setBold(True)
            it.setFont(1, f)
            if not self._has_sev:
                self._has_sev = True
                self.tree.setColumnHidden(1, False)
        self.tree.addTopLevelItem(it)
        return it

    def _clear_results(self):
        """Clear the results and collapse the Severity column again — it reappears only if the next tool reports a
        severity, so tools that don't (technologies, JS endpoints, …) never show a blank column."""
        self.tree.clear()
        self._has_sev = False
        self.tree.setColumnHidden(1, True)

    def port_scan(self):
        host = self._host()
        if not self._authorized(host, "Port scanning"):
            return
        nmap, versions = self.use_nmap.isChecked(), self.versions.isChecked()

        def render(r):
            self._clear_results()
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
            self._clear_results()
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
        if not self.target.text().strip():
            self.use_current()
        try:  # domain / URL / host:port / IP / CIDR / ASN -> exactly what this tool needs
            target = pdtools.target_for(tool, self.target.text())
        except ValueError as e:
            self.status.setText(str(e))
            return
        if tool.active and not self._authorized(self._host(), f"{tool.name}"):
            return
        self._clear_results()
        self._pd_running = True
        self.pd_run.setEnabled(False)
        self.pd_stop.setEnabled(True)
        self.busy.start(f"{tool.name} running…")
        shown = target.replace("?//", "") if target.startswith("?//") else target
        self.status.setText(f"Running {tool.name} on {shown} …")
        self._pd_count = 0
        self._pd_stop_flag = False
        px = self.win.proxies()
        eng = self.win.engagement
        scope = list(eng.scope) if eng and eng.scope else []
        try:   # B8: enforced again in pdtools.run(); checked here too so a CIDR range is judged as a whole
            pdtools.check_scope(tool, target, scope)
        except pdtools.OutOfScope as e:
            self._pd_running = False
            self.pd_run.setEnabled(True)
            self.pd_stop.setEnabled(False)
            self.busy.stop()
            self.status.setText(str(e))
            return

        def work():
            t = pdtools.probe_scheme(target, px)  # no http(s):// typed: use https if the site answers, else http
            if t != target:
                self._pd_status.emit(f"Running {tool.name} on {t} …")
            return pdtools.run(tool, t, lambda text, obj: self._pd_line.emit(text, obj), proxies=px,
                               should_stop=lambda: self._pd_stop_flag, scope=scope)
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
            self._clear_results()
            self._add(f"Clickjacking: {r['verdict']}", r["severity"],
                      f"{sev_badge(r['severity'])} {escape(r['verdict'])}<br><br>X-Frame-Options: <code>"
                      f"{escape(r['x_frame_options'] or '(none)')}</code><br>CSP frame-ancestors: <code>"
                      f"{escape(r['frame_ancestors'] or '(none)')}</code><br><br>Use <b>Framing proof-of-concept</b> "
                      f"to see it framed.<br><i>Method: {escape(r['paper'])}</i>", {"url": url})
            self.status.setText(f"Clickjacking check on {url}: HTTP {r['status']}.")
        self._run("Clickjacking test", lambda: webchecks.clickjacking_test(url, px, verify), render)

    def technologies(self):
        """Wappalyzer-style technology detection for the target (built in: bundled httpx + wappalyzergo)."""
        if not self.target.text().strip():
            self.use_current()
        try:
            target = pdtools.target_for(pdtools.TECH_TOOL, self.target.text())
        except ValueError as e:
            self.status.setText(str(e))
            return
        px = self.win.proxies()
        def render(r):
            self._clear_results()
            blocked = r["status"] in (202, 403, 429, 503) and not [n for n, _ in r["tech"] if n.lower() not in
                                                                    ("cloudflare", "http/3", "hsts")]
            info = (f"<b>{escape(r['final_url'])}</b><br>HTTP {escape(str(r['status']))}"
                    + (f" · Server: {escape(r['server'])}" if r["server"] else "")
                    + (f" · CDN/WAF: {escape(r['cdn'])}" if r["cdn"] else "")
                    + (f"<br>Title: {escape(r['title'])}" if r["title"] else ""))
            if blocked and not r.get("from_page"):
                info += ("<br><br><i>The site answered with a bot check / block page, so only its protection "
                         "layer could be identified. Open the site in a tab and run Technologies with the target "
                         "empty: Wyrm then analyses the page your browser received.</i>")
            cats = r.get("cats") or {}
            icons = r.get("icons")
            if icons is None:  # remote (httpx) path: map names to the Wappalyzer icon files ourselves
                icons = {name: techdetect.icon_for(name) for name, _ in r["tech"]}
            icons = {k: v for k, v in icons.items() if v}
            logo_items = {}   # name -> tree item, for the lazy logo loader
            from urllib.parse import quote_plus
            for name, ver in r["tech"]:
                q = quote_plus(f"{name} {ver}".strip())
                cve = (f"<br><br><b>Known vulnerabilities</b><br>"
                       f"<a href='wyrm://sec?q={q}'>Search Wyrm (CVE / KEV / EPSS)</a> · "
                       f"<a href='https://nvd.nist.gov/vuln/search/results?query={q}'>NVD</a> · "
                       f"<a href='https://www.cvedetails.com/google-search-results.php?q={q}'>CVE Details</a>"
                       + ("" if ver else "<br><i>No version detected — results will be broad.</i>"))
                it = self._add(name + (f"  {ver}" if ver else "") + (f"   · {cats[name]}" if cats.get(name) else ""), "",
                               f"<b>{escape(name)}</b>{' version ' + escape(ver) if ver else ''}"
                               + (f"<br><span style='color:#8d8d8d'>{escape(cats[name])}</span>" if cats.get(name) else "")
                               + f"<br><br>{info}{cve}",
                               {"url": r["final_url"]})
                if icons.get(name):
                    logo_items[name] = it
            self._load_tech_logos(logo_items, icons)
            if not r["tech"]:
                self._add("No technologies identified", "", info, {"url": r["final_url"]})
            self.status.setText(f"{len(r['tech'])} technolog{'y' if len(r['tech']) == 1 else 'ies'} on "
                                f"{r['final_url']}" + (" (from the open page)" if r.get("from_page") else
                                                       " (bot check: partial)" if blocked else "") + ".")
            if self.tree.topLevelItemCount():
                self.tree.setCurrentItem(self.tree.topLevelItem(0))

        # The page you have open: analyse what the browser actually received (HTML + response headers), like
        # Wappalyzer does. Works past bot checks / logins and doesn't contact the site again.
        view = self.win.current_view()
        page = getattr(view, "resp_headers", None) if view else None
        cur = view.url() if view else None
        t_host = (urlparse(target.replace("?//", "https://", 1)).hostname or "").lower()
        if page and cur is not None and cur.scheme() in ("http", "https") and cur.host().lower() == t_host:
            headers = page[1]

            def with_fp(ok, fp):
                if not ok:
                    self.busy.stop()
                    self.status.setText(f"Technology detection failed: {fp}")
                    return
                self.win._tech_fp = fp
                from PySide6.QtWebEngineCore import QWebEngineScript
                view.page().runJavaScript(techdetect.collect_js(fp), QWebEngineScript.ScriptWorldId.MainWorld,
                                          lambda res: got(fp, res))

            def got(fp, res):
                import json

                def work():
                    ev = json.loads(res or "{}")
                    found = techdetect.analyze(fp, ev, headers)
                    server = next((v for k, v in headers.items() if k.lower() == "server"), "")
                    return {"url": cur.toString(), "final_url": cur.toString(), "status": 200, "title": view.title(),
                            "server": server.splitlines()[0] if server else "", "cdn": "", "from_page": True,
                            "tech": [(f["name"], f["version"]) for f in found],
                            "cats": {f["name"]: ", ".join(f["categories"]) for f in found},
                            "icons": {f["name"]: f["icon"] for f in found if f.get("icon")}}
                self.busy.stop()
                self._run("Matching technologies", work, render)

            fp = getattr(self.win, "_tech_fp", None)
            self.busy.start("Detecting technologies on this page…")
            self.status.setText("Detecting technologies on this page…")
            if fp is not None:
                with_fp(True, fp)
            else:
                cache = self.win.data_dir / "tech"
                self.win.runner.run(lambda: techdetect.Fingerprints.load(cache), with_fp)
        else:
            def work():
                return pdtools.detect_technologies(pdtools.probe_scheme(target, px), px)
            self._run("Detecting technologies", work, render)

    def _load_tech_logos(self, items: dict, icons: dict):
        """Fetch each detected technology's logo (Wappalyzer MIT icon set) off-thread and show it on its row."""
        if not items:
            return
        cache = self.win.data_dir / "tech-icons"
        px, verify = self.win.proxies(), self.win.verify_tls()
        want = {name: icons[name] for name in items if icons.get(name)}

        def work():
            for name, icon in want.items():
                try:
                    p = techdetect.ensure_icon(icon, cache, px, verify)
                except Exception:  # noqa: BLE001
                    p = None
                if p:
                    self._logo_ready.emit(items[name], str(p))
            return True
        self.win.runner.run(work, lambda *_: None)

    def _set_logo(self, item, path):
        from PySide6.QtGui import QIcon
        try:
            if item is not None and path:
                item.setIcon(0, QIcon(path))
        except RuntimeError:  # item was removed (a new scan cleared the tree)
            pass

    def frame_poc(self):
        url = self._url()
        if url:
            self.win.open_url("wyrm://frametest?u=" + quote(url, safe=""), new_tab=True)

    # ---------------------------------------------------------------- JS recon (endpoints + secrets)
    def js_recon(self):
        """Pull endpoints and leaked secrets from the target's scripts. Uses the Target field (not just the open
        tab) and is scope-gated: no network request is sent for an out-of-scope host (QA-H3)."""
        base = self._url()
        host = self._host()
        if not base or not host:
            QMessageBox.information(self, "JS recon",
                                    "Enter a target URL in the Target field (or open the page), then run JS recon.")
            return
        view = self.win.current_view()
        cur = view.url() if view else None
        cur_url = cur.toString() if (cur and cur.scheme() in ("http", "https")) else ""
        eng = self.win.engagement
        in_scope = bool(eng and eng.scope and eng.in_scope(host) is True)
        plan = _js_plan(base, cur_url, in_scope)
        if plan == "refuse":
            self._authorized(host, "JS recon")   # modal refusal; nothing is sent
            return
        if plan == "fetch":
            self._js_from_fetch(base)
        else:   # "dom" (in scope) or "dom_inline" (out of scope: inline only, no external fetch)
            self._js_from_dom(view, base, fetch_external=(plan == "dom"))

    def _analyze_blobs(self, blobs, inline_count, external_count, base) -> dict:
        endpoints, secrets = set(), []
        for b in blobs:
            endpoints.update(jsrecon.find_endpoints(b, base))
            for name, snippet, sev in jsrecon.find_secrets(b):
                secrets.append((name, snippet, sev))
        uniq, seen = [], set()
        for s in secrets:
            if s not in seen:
                seen.add(s)
                uniq.append(s)
        return {"endpoints": jsrecon.rank_endpoints(endpoints, base), "secrets": uniq,
                "inline": inline_count, "external": external_count, "base": base}

    def _js_from_dom(self, view, base, fetch_external: bool):
        """Read scripts from the live same-origin tab. External scripts are fetched only when in scope."""
        px, verify = self.win.proxies(), self.win.verify_tls()
        self.busy.start("Reading page scripts…")
        self.status.setText("JS recon: reading the page's scripts…")
        js = ("(function(){var s=document.getElementsByTagName('script'),src=[],inl=[];"
              "for(var i=0;i<s.length;i++){if(s[i].src)src.push(s[i].src);"
              "else if(s[i].textContent)inl.push(s[i].textContent);}"
              "return JSON.stringify({src:src,inline:inl});})();")

        def have_scripts(res):
            import json
            try:
                data = json.loads(res or "{}")
            except ValueError:
                data = {}
            inline = data.get("inline") or []
            srcs = jsrecon.scripts_to_fetch(data.get("src") or [], base) if fetch_external else []

            def work():
                import requests
                blobs, scanned = list(inline), 0
                for u in srcs[:40]:   # cap so a huge app can't run forever
                    try:
                        r = requests.get(u, timeout=20, proxies=px, verify=verify,
                                         headers={"User-Agent": "Mozilla/5.0 Wyrm JS recon"})
                        if r.status_code == 200 and len(r.content) < 8_000_000:
                            blobs.append(r.text)
                            scanned += 1
                    except requests.RequestException:
                        pass
                return self._analyze_blobs(blobs, len(inline), scanned, base)
            self.status.setText(f"JS recon: scanning {len(inline)} inline + {len(srcs)} external script(s)…")
            self._run("JS recon", work, self._js_render)
        view.page().runJavaScript(js, have_scripts)

    def _js_from_fetch(self, base):
        """Download the target page (a different origin than the open tab) and scan its scripts — in scope only."""
        px, verify = self.win.proxies(), self.win.verify_tls()
        self.busy.start("Fetching target scripts…")
        self.status.setText("JS recon: fetching the target page…")

        def work():
            import requests
            ua = {"User-Agent": "Mozilla/5.0 Wyrm JS recon"}
            page = requests.get(base, timeout=20, proxies=px, verify=verify, headers=ua)
            ext = _ScriptExtract()
            ext.feed(page.text if page.status_code == 200 else "")
            srcs = jsrecon.scripts_to_fetch(ext.src, base)
            blobs, scanned = list(ext.inline), 0
            for u in srcs[:40]:
                try:
                    r = requests.get(u, timeout=20, proxies=px, verify=verify, headers=ua)
                    if r.status_code == 200 and len(r.content) < 8_000_000:
                        blobs.append(r.text)
                        scanned += 1
                except requests.RequestException:
                    pass
            return self._analyze_blobs(blobs, len(ext.inline), scanned, base)
        self._run("JS recon", work, self._js_render)

    def _js_render(self, r):
        self._clear_results()
        for name, snippet, sev in r["secrets"]:
            self._add(f"Secret: {name}", sev,
                      f"{sev_badge(sev)} <b>{escape(name)}</b><br><br><code>{escape(snippet)}</code>"
                      "<br><br>Found in the page's JavaScript. Verify it is live and in scope before reporting.",
                      {"url": r["base"]})
        for absolute, shown, interesting in r["endpoints"]:
            # QA-M1: 'warning' isn't a severity level — interesting endpoints are 'info' plus the ★ marker
            self._add(("★ " if interesting else "") + shown, "info" if interesting else "",
                      f"<b>Endpoint</b><br><br><a href='{escape(absolute)}'>{escape(absolute)}</a>"
                      + ("<br><br>Flagged as interesting (admin / token / api / graphql …).</i>" if interesting else ""),
                      {"url": absolute})
        ne, ns = len(r["endpoints"]), len(r["secrets"])
        if not ne and not ns:
            self._add("Nothing found in the page's scripts", "", "No endpoints or secrets matched.", {"url": r["base"]})
        self.status.setText(f"JS recon: {ns} secret(s), {ne} endpoint(s) from "
                            f"{r['inline']} inline + {r['external']} external script(s).")
        if self.tree.topLevelItemCount():
            self.tree.setCurrentItem(self.tree.topLevelItem(0))

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
