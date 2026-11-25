#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/recon.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Security panel → Recon: crt.sh, Wayback, well-known files and ProjectDiscovery Chaos."""
from __future__ import annotations

import ipaddress
from html import escape
from urllib.parse import urlparse

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import QCheckBox, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, QMessageBox, QPushButton, QVBoxLayout, QWidget

from .common import mono
from ..security import chaos, intel
from ..widgets import SkeletonOverlay


def _host_from_text(text: str) -> str:
    """Extract just the host from a typed target or a URL: strip scheme, userinfo, port and path, so
    'http://user@127.0.0.1:8777/p', '127.0.0.1:8777' and 'example.com/x' all reduce to the bare host.
    Returns '' for internal/non-network URLs (wyrm://home → '', not 'home') — BUG-1."""
    t = (text or "").strip()
    if not t:
        return ""
    if "://" in t:                                    # a full URL: honour its scheme
        u = urlparse(t)
        if u.scheme not in ("http", "https", "ftp"):
            return ""                                 # wyrm://, file://, data: … are not recon targets
    else:                                             # a bare 'host', 'host:port', or 'scheme:path'
        head = t.split(":", 1)[0].lower()
        if head in ("about", "mailto", "data", "javascript", "file", "tel", "wyrm", "blob", "chrome", "view-source"):
            return ""                                 # about:blank, mailto:…, etc. — not a host:port
        u = urlparse("//" + t)                        # add '//' so 'host:port' parses as authority
    host = (u.hostname or "").strip(".")              # urlparse.hostname is lowercased and port/userinfo-free
    return host[4:] if host.startswith("www.") else host


def _origin_from(text: str, stored: str = ""):
    """Derive (origin, host) for a well-known lookup, preserving the real scheme and port (QA-H2):
      - a full URL keeps its scheme + netloc ('http://127.0.0.1:8765/x' -> 'http://127.0.0.1:8765'),
      - a host:port keeps the port (non-443 -> http),
      - a bare hostname defaults to https://,
      - a `stored` origin (from 'Use current') wins when it's for the same host.
    Returns (None, None) when there's no host."""
    text = (text or "").strip()
    host = _host_from_text(text)
    if not host:
        return None, None
    if stored and _host_from_text(stored) == host:
        return stored, host
    if "://" in text:
        p = urlparse(text)
        scheme = p.scheme if p.scheme in ("http", "https") else "https"
        return f"{scheme}://{p.netloc}", host
    netloc = text.split("/")[0]                       # host or host:port
    port = netloc.rsplit(":", 1)[1] if ":" in netloc and netloc.rsplit(":", 1)[1].isdigit() else ""
    scheme = "https" if (not port or port == "443") else "http"
    return f"{scheme}://{netloc}", host


def _is_ip_or_local(host: str) -> bool:
    """True for IP literals and localhost — crt.sh certificate-transparency search doesn't apply to them."""
    h = host.strip("[]")
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


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
        self._source_btns = []   # QA-L2: disabled while a lookup is running so clicks aren't silently dropped
        for label, fn, tip in (
                ("Subdomains (crt.sh)", self.subdomains, "Certificate transparency logs"),
                ("Wayback URLs", self.wayback, "Archived URLs from the Internet Archive"),
                ("robots / sitemap / security.txt", self.well_known, "What the site publishes about itself"),
                ("ProjectDiscovery Chaos", self.chaos_search,
                 "Search ProjectDiscovery's public bug-bounty recon dataset by program name or domain")):
            b = QPushButton(label)
            b.setToolTip(tip)
            b.clicked.connect(fn)
            row2.addWidget(b)
            self._source_btns.append(b)
        self._chaos_programs: dict[str, dict] = {}  # result-list text -> Chaos program
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
        self.busy = SkeletonOverlay(self.list)
        self.status = QLabel("Passive sources only: certificate transparency logs, the Internet Archive and "
                             "ProjectDiscovery Chaos.")
        self.status.setObjectName("Muted")
        self.status.setWordWrap(True)
        v.addWidget(self.status)

    def use_current(self):
        v = self.win.current_view()
        u = v.url() if v else None
        if u is None or u.scheme() not in ("http", "https", "ftp"):
            self.status.setText("Open an http(s) site first, then “Use current”.")
            return
        host = u.host()                               # QUrl.host(): no scheme/port/userinfo/path
        # QA-H2: remember the full origin (scheme + non-default port) for the well-known lookup, which must not
        # be forced to https:// on the default port. crt.sh/Wayback/Chaos still use the host alone.
        port = u.port()
        self._origin_url = f"{u.scheme()}://{host}" + (f":{port}" if port > 0 and port not in (80, 443) else "")
        self.domain.setText(host[4:] if host.startswith("www.") else host)

    def _origin(self):
        """(origin, host) for the well-known lookup: the last 'Use current' origin when it matches the box, else
        derived from the typed text. See _origin_from() (QA-H2)."""
        text = self.domain.text().strip()
        if not text:
            self.use_current()
            text = self.domain.text().strip()
        return _origin_from(text, getattr(self, "_origin_url", ""))

    def _target(self) -> str | None:
        d = _host_from_text(self.domain.text())
        if not d:
            self.use_current()
            d = _host_from_text(self.domain.text())
        if not d:
            return None
        eng = self.win.engagement
        if eng and eng.scope and not eng.in_scope(d):
            self.items = []           # QA-L2: don't leave the previous lookup's results under a new message
            self._render()
            QMessageBox.warning(self, "Out of scope", f"{d} is not in the scope of '{eng.name}'.")
            return None
        return d

    def _set_busy(self, on: bool):
        for b in getattr(self, "_source_btns", []):   # QA-L2: don't let the busy overlay silently swallow clicks
            b.setEnabled(not on)

    def _run(self, label, fn, render):
        d = self._target()
        if not d:
            return
        self.status.setText(f"{label} for {d}…")
        self.busy.start(f"{label} for {d}…")
        self._set_busy(True)

        def done(ok, r):
            self.busy.stop()
            self._set_busy(False)
            render(d, r) if ok else self.status.setText(f"{label} failed: {r}")
        self.win.runner.run(fn, done, d)

    def subdomains(self):
        d = self._target()
        if not d:
            return
        if _is_ip_or_local(d):                        # BUG-1: crt.sh has no subdomains for an IP/localhost
            self.items = []                           # QA-L2: clear old results before the guard message
            self._render()
            self.status.setText(f"{d} is an IP address or localhost — certificate-transparency subdomain "
                                "search only works for registered domain names.")
            return

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
        origin, host = self._origin()
        if not origin:
            return
        eng = self.win.engagement
        if eng and eng.scope and not eng.in_scope(host):
            self.items = []
            self._render()
            QMessageBox.warning(self, "Out of scope", f"{host} is not in the scope of '{eng.name}'.")
            return

        def render(_d, r):
            self.items = []
            for name in ("security.txt", "robots.txt", "sitemap.xml"):
                x = r[name]
                if x["status"] is None:               # QA-H2: a refused/failed connection, not a 404
                    self.items.append((f"── {name}: request failed ({x.get('error', 'no response')})", ""))
                    continue
                self.items.append((f"── {name}: {'found' if x['found'] else 'not found'} (HTTP {x['status']})", ""))
                if name == "security.txt" and x["found"]:
                    self.items += [(f"   {line}", "disclosure policy") for line in x["text"].splitlines()[:30] if line.strip()]
            self.items += [(u, "Disallow in robots.txt") for u in r["disallowed"]]
            self.items += [(u, "sitemap") for u in r["sitemap_urls"]]
            self.status.setText(f"{len(r['disallowed'])} disallowed paths · {len(r['sitemap_urls'])} sitemap URLs "
                                f"for {origin}. security.txt tells you how the owner wants vulnerabilities reported.")
            self._render()
        self.status.setText(f"Well-known files for {origin}…")
        self.busy.start("Well-known files…")
        self._set_busy(True)

        def done(ok, r):
            self.busy.stop()
            self._set_busy(False)
            render(origin, r) if ok else self.status.setText(f"Well-known files failed: {r}")
        self.win.runner.run(intel.well_known, done, origin)

    # ---- ProjectDiscovery Chaos (public bug-bounty recon data) — developer: @oda
    def chaos_search(self):
        q = self.domain.text().strip()
        if not q:
            self.use_current()
            q = self.domain.text().strip()
        if not q:
            self.status.setText("Type a program name (e.g. tesla) or a domain, then search ProjectDiscovery Chaos.")
            return
        px, verify = self.win.proxies(), self.win.verify_tls()
        self.status.setText(f"Searching ProjectDiscovery Chaos for “{q}”…")
        self.busy.start("Searching ProjectDiscovery Chaos…")
        self._set_busy(True)

        def done(ok, progs):
            self.busy.stop()
            self._set_busy(False)
            if not ok:
                self.status.setText(f"ProjectDiscovery Chaos search failed: {progs}")
                return
            self._chaos_programs = {}
            self.items = []
            for p in progs:
                text = (f"◆ {p['name']} · {p['platform']} · {'bounty' if p['bounty'] else 'no bounty'} · "
                        f"{p['count']:,} subdomains · updated {p['updated']}")
                self._chaos_programs[text] = p
                self.items.append((text, p["program_url"] or "ProjectDiscovery Chaos program"))
            self.status.setText(
                f"{len(progs)} ProjectDiscovery Chaos program(s) match “{q}”. Double-click a program to load its "
                "subdomains." if progs else f"No ProjectDiscovery Chaos program matches “{q}”.")
            self._render()
        self.win.runner.run(lambda: chaos.search(q, px, verify), done)

    def _chaos_load(self, prog: dict):
        px, verify = self.win.proxies(), self.win.verify_tls()
        self.status.setText(f"Loading {prog['count']:,} subdomains for {prog['name']} from ProjectDiscovery Chaos…")
        self.busy.start(f"Loading {prog['name']} from Chaos…")
        self._set_busy(True)

        def done(ok, hosts):
            self.busy.stop()
            self._set_busy(False)
            if not ok:
                self.status.setText(f"Couldn't load {prog['name']}: {hosts}")
                return
            eng = self.win.engagement
            self.items = [(h, "in scope" if eng and eng.in_scope(h) else "") for h in hosts]
            self._chaos_programs = {}
            self.status.setText(f"{len(hosts):,} subdomains for {prog['name']} ({prog['platform']}) from ProjectDiscovery "
                                "Chaos. Only test what the program's scope allows — double-click to open.")
            self._render()
        self.win.runner.run(lambda: chaos.subdomains(prog, px, verify), done)

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
            it = QListWidgetItem(text)   # list labels are plain text (inert); tooltips auto-render rich text
            # show the full line + its note on hover so clipped security.txt lines / long URLs stay readable
            # (L-7), escaped so target/API data can't inject rich text into the tooltip (SEC-6)
            it.setToolTip(escape(text + (f"\n{tip}" if tip else "")))
            if text in self._chaos_programs:  # clickable Chaos program row
                f = it.font()
                f.setBold(True)
                it.setFont(f)
                it.setForeground(QBrush(QColor("#4589ff")))
            elif tip == "in scope" or intel.INTERESTING_URL.search(text):
                it.setForeground(QBrush(QColor("#1e8e3e" if tip == "in scope" else "#fa7b17")))
            self.list.addItem(it)

    def _open(self, it):
        t = it.text().strip()
        if t in self._chaos_programs:  # a Chaos program row: load its subdomains
            self._chaos_load(self._chaos_programs[t])
            return
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
        if it and it.text().strip() in self._chaos_programs:
            prog = self._chaos_programs[it.text().strip()]
            m = QMenu(self)
            m.addAction("Load subdomains", lambda: self._chaos_load(prog))
            if prog["program_url"]:
                m.addAction("Open program page (scope && rules)", lambda: self.win.open_url(prog["program_url"], new_tab=True))
            m.exec(self.list.viewport().mapToGlobal(pos))
            return
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
