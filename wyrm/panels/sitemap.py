#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/sitemap.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Security panel → Site map: host/path tree from browsing plus robots/sitemap discovery."""
from __future__ import annotations

from html import escape
from urllib.parse import urlparse

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget


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
                it.setToolTip(0, escape(e["url"]))  # tooltips auto-render rich text; keep target URLs inert (SEC-6)
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
        from ..security import discover
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
