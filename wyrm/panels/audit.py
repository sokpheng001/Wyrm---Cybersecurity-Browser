#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/audit.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Security panel → Audit: active vulnerability scan of a single request (from Proxy / Repeater).

Send a request here ("Scan this request"), and Wyrm fuzzes its insertion points (params, path segments, cookies,
headers) for reflected XSS, SQL injection (error + blind), command injection, SSRF, SSTI, path traversal, XXE,
CORS, host-header injection, GraphQL introspection, open redirect and CRLF, plus passive response checks
(exposed secrets/tokens/cards, weak JWTs, mixed content, CSRF) — results stream in and can be added
to Findings. Active scanning only runs on hosts inside the current engagement scope.
"""
from __future__ import annotations

from html import escape
from urllib.parse import parse_qsl, urlparse, urlsplit

import requests

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (QComboBox, QHBoxLayout, QHeaderView, QLabel, QMessageBox, QPushButton, QSplitter,
                               QTextBrowser, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from .common import SEV_COLOR, sev_badge, sev_title
from ..security.audit import engine
from ..security.audit.advice import advice as _advice
from ..widgets import SkeletonOverlay


class _OobBridge:
    """Lets the SSRF / command-injection checks use the running OOB listener (callback correlation)."""

    def __init__(self, panel):
        self.p = panel

    def token(self) -> str:
        from ..security.oob import InteractionServer
        return InteractionServer.new_token()

    def url(self, token):
        return self.p.oob_payload(token)

    def wait_hit(self, token, timeout) -> bool:
        import time
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self.p.oob_hit(token):
                return True
            time.sleep(0.5)
        return False


class AuditTab(QWidget):
    _finding = Signal(object)
    _done = Signal(bool, object)
    _progress = Signal(int, int, str)

    def __init__(self, win):
        super().__init__()
        self.win = win
        self._req = None
        self._running = False
        self._stop_flag = False
        self._finding.connect(self._on_finding)
        self._done.connect(self._on_done)
        self._progress.connect(self._on_progress)
        # coalesce the footer/button refresh so a burst of findings doesn't starve the UI thread (which would make
        # the app sluggish and could crash a new tab trying to start QtWebEngine mid-scan)
        self._ui_refresh = QTimer(self, singleShot=True, interval=120)
        self._ui_refresh.timeout.connect(self._flush_ui_refresh)

        v = QVBoxLayout(self)
        intro = QLabel("<b>Audit</b> — active vulnerability scan of one request. From the <b>Proxy</b> history or "
                       "<b>Repeater</b>, right-click → <b>Scan this request</b>. It fuzzes each parameter and URL "
                       "path segment for reflected XSS, SQL injection (error / blind boolean / blind time-based), "
                       "command injection, SSRF (incl. cloud metadata), SSTI, path traversal, XXE, CORS and "
                       "host-header injection, GraphQL introspection, open redirect and CRLF — plus passive checks "
                       "for exposed secrets, tokens, cards, weak JWTs, mixed content and missing CSRF tokens. "
                       "Active scanning only runs on hosts in your engagement scope.")
        intro.setObjectName("Muted")
        intro.setWordWrap(True)
        v.addWidget(intro)

        row = QHBoxLayout()
        self.target = QLabel("No request loaded. Send one here from Proxy or Repeater.")
        self.target.setWordWrap(True)
        row.addWidget(self.target, 1)
        self.intensity = QComboBox()
        self.intensity.addItems(["Thorough", "Fast", "Passive only"])
        self.intensity.setToolTip("Thorough: all checks incl. the slow time-based probe. Fast: skip the slow "
                                  "time-based command-injection probe. Passive only: no payloads sent.")
        row.addWidget(self.intensity)
        self.b_run = QPushButton("Run scan")
        self.b_run.setObjectName("Primary")
        self.b_run.setEnabled(False)
        self.b_run.clicked.connect(self._run)
        row.addWidget(self.b_run)
        self.b_site = QPushButton("Scan in-scope traffic")
        self.b_site.setToolTip("Audit every in-scope request Wyrm has seen through the proxy (browse the app first).")
        self.b_site.clicked.connect(self._run_site)
        row.addWidget(self.b_site)
        self.b_crawl = QPushButton("Crawl + scan")
        self.b_crawl.setToolTip("Spider the current in-scope site (follow links & forms), then audit what it finds.")
        self.b_crawl.clicked.connect(self._run_crawl)
        row.addWidget(self.b_crawl)
        self.b_stop = QPushButton("Stop")
        self.b_stop.setEnabled(False)
        self.b_stop.clicked.connect(self._stop)
        row.addWidget(self.b_stop)
        v.addLayout(row)

        split = QSplitter(Qt.Orientation.Vertical)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Issue", "Severity", "Parameter", "Confidence"])
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.currentItemChanged.connect(self._show)
        split.addWidget(self.tree)
        self.busy = SkeletonOverlay(self.tree)
        self.detail = QTextBrowser()
        self.detail.setOpenLinks(False)
        self.detail.anchorClicked.connect(lambda u: self.win.open_url(u.toString(), new_tab=True))
        split.addWidget(self.detail)
        split.setSizes([320, 180])
        v.addWidget(split, 1)

        foot = QHBoxLayout()
        self.status = QLabel("")
        self.status.setObjectName("Muted")
        self.status.setWordWrap(True)
        foot.addWidget(self.status, 1)
        self.b_add = QPushButton("Add to findings")
        self.b_add.clicked.connect(self._add_finding)
        self.b_add.setEnabled(False)
        self.b_add.setToolTip("Select a result to record it as a finding")
        foot.addWidget(self.b_add)
        self.b_add_all = QPushButton("Add all")
        self.b_add_all.clicked.connect(self._add_all)
        self.b_add_all.setEnabled(False)
        self.b_add_all.setToolTip("Run a scan first — there are no results to add")
        foot.addWidget(self.b_add_all)
        self.tree.currentItemChanged.connect(lambda *_: self._update_add_buttons())
        v.addLayout(foot)

    def _update_add_buttons(self):
        """QA-L3: enable the add buttons only when there are results (and a selection, for 'Add to findings')."""
        has_rows = self.tree.topLevelItemCount() > 0
        self.b_add_all.setEnabled(has_rows)
        self.b_add.setEnabled(has_rows and self.tree.currentItem() is not None)

    # ------------------------------------------------------------ load + authorize
    def scan_request(self, method, url, headers: dict, body: str):
        self._req = {"method": method or "GET", "url": url, "headers": dict(headers or {}), "body": body or ""}
        host = (urlparse(url).hostname or "")
        self.target.setText(f"<b>{escape(method or 'GET')}</b> {escape(url)}")
        self.b_run.setEnabled(True)
        self.tree.clear()
        self._update_add_buttons()
        self.detail.clear()
        self.win.security.show()
        self.win.security.show_tab("Audit")
        if self._authorized(host):
            self._run()
        else:
            self.status.setText(f"{host} is not in your engagement scope — add it to scan (passive checks only "
                                "otherwise).")

    def _authorized(self, host: str) -> bool:
        eng = self.win.engagement
        return bool(host and eng and eng.scope and eng.in_scope(host) is True)

    # ------------------------------------------------------------ run
    def _run(self):
        if self._running or not self._req:
            return
        host = urlparse(self._req["url"]).hostname or ""
        if not self._authorized(host):
            QMessageBox.information(self, "Authorized targets only",
                                    "Active scanning only runs on hosts in your engagement scope.\n\n"
                                    f"Add {host} to an engagement (dropdown left of the address bar), and only test "
                                    "systems you own or have written permission to test.")
            return
        import requests
        self.tree.clear()
        self._update_add_buttons()
        self.detail.clear()
        self._running = True
        self._stop_flag = False
        self._count = 0
        self.b_run.setEnabled(False)
        self.b_stop.setEnabled(True)
        self.busy.start("Auditing…")
        self.status.setText("Auditing… payloads are only sent to the in-scope target.")
        req = self._req
        send = self._make_send()
        oob = self._oob_bridge()
        checks = self._selected_checks()

        def work():
            return engine.scan(req, send, should_stop=lambda: self._stop_flag,
                               on_finding=lambda f: self._finding.emit(f), oob=oob, checks=checks)
        self.win.runner.run(work, lambda ok, res: self._done.emit(bool(ok), res))

    def _selected_checks(self):
        from ..security.audit import checks as chk
        mode = self.intensity.currentText()
        if mode.startswith("Passive"):
            return []
        # Fast drops the slow time-based probes; Thorough runs everything. Add-on-registered checks run in both.
        base = chk.standard(time_based=not mode.startswith("Fast"))
        extra = list(getattr(self.win, "_addon_scan_checks", []))
        return base + extra

    def _make_send(self):
        px, verify = self.win.proxies(), self.win.verify_tls()

        def send(method, url, headers, body):
            try:
                # stream so we can cap how much we pull into memory — a scan runs several of these at once, and
                # multi-MB responses would otherwise spike memory/CPU (and could crash the app, especially while
                # new tabs are loading). 2 MB is plenty for reflection/secret/error checks.
                r = requests.request(method, url, headers=headers, data=(body or None), proxies=px, verify=verify,
                                     allow_redirects=False, timeout=15, stream=True)
                raw_bytes = r.raw.read(2_000_000, decode_content=True) or b""
                r._content = raw_bytes          # so r.text decodes the capped body with the right charset
                r._content_consumed = True
                text = r.text
            except requests.RequestException:
                return None
            except Exception:  # noqa: BLE001 - a malformed/oversized body must never crash the scan
                return None
            finally:
                try:
                    r.close()
                except Exception:  # noqa: BLE001
                    pass
            H = {k.lower(): v for k, v in r.headers.items()}
            sc = [H["set-cookie"]] if "set-cookie" in H else []
            return {"status": r.status_code, "headers": H, "text": text, "location": H.get("location", ""),
                    "url": url, "set_cookie": sc}
        return send

    def _oob_bridge(self):
        oob_panel = getattr(self.win.security, "oob", None)
        return _OobBridge(oob_panel) if (oob_panel is not None and oob_panel.oob_active()) else None

    # ------------------------------------------------------------ scan the whole in-scope attack surface
    def _collect_targets(self):
        """Unique in-scope requests seen through the proxy (requests with parameters first). Bounded."""
        from ..security import mitm
        eng = self.win.engagement
        flows = list(mitm.ACTIVE.flows) if mitm.ACTIVE is not None else []
        seen, with_params, without = set(), [], []
        for fl in flows:
            host = fl.get("host", "")
            if not (eng and eng.scope and eng.in_scope(host) is True):
                continue
            url = fl.get("url", "")
            parts = urlsplit(url)
            qnames = tuple(sorted(k for k, _ in parse_qsl(parts.query, keep_blank_values=True)))
            body = _as_text(fl.get("req_body", b""))
            key = (fl.get("method", "GET"), host, parts.path, qnames, bool(body))
            if key in seen:
                continue
            seen.add(key)
            req = {"method": fl.get("method", "GET"), "url": url,
                   "headers": dict(fl.get("req_headers", [])), "body": body}
            (with_params if (qnames or body) else without).append(req)
        return (with_params + without)[:150]

    def _run_site(self):
        if self._running:
            return
        reqs = self._collect_targets()
        if not reqs:
            QMessageBox.information(self, "Scan in-scope traffic",
                                   "No in-scope requests captured yet.\n\nTurn on the intercepting proxy (Proxy tab), "
                                   "set an engagement scope, browse the target, then run this.")
            return
        self.tree.clear()
        self._update_add_buttons()
        self.detail.clear()
        self._running = True
        self._stop_flag = False
        self._count = 0
        self.b_run.setEnabled(False)
        self.b_site.setEnabled(False)
        self.b_stop.setEnabled(True)
        self.busy.start("Auditing site…")
        self.status.setText(f"Auditing {len(reqs)} in-scope request(s)…")
        send = self._make_send()
        oob = self._oob_bridge()
        checks = self._selected_checks()

        def work():
            return engine.scan_site(reqs, send, should_stop=lambda: self._stop_flag,
                                    on_finding=lambda f: self._finding.emit(f), oob=oob, checks=checks,
                                    on_progress=lambda d, n, u: self._progress.emit(d, n, u))
        self.win.runner.run(work, lambda ok, res: self._done.emit(bool(ok), res))

    def _run_crawl(self):
        if self._running:
            return
        view = self.win.current_view()
        cur = view.url().toString() if view else ""
        host = urlparse(cur).hostname or ""
        eng = self.win.engagement
        if not cur.startswith(("http://", "https://")) or not (eng and eng.scope and eng.in_scope(host) is True):
            QMessageBox.information(self, "Crawl + scan",
                                   "Open an in-scope page in a tab first (and set an engagement scope), then "
                                   "Crawl + scan — the spider only follows links on in-scope hosts.")
            return
        self.tree.clear()
        self._update_add_buttons()
        self.detail.clear()
        self._running = True
        self._stop_flag = False
        self._count = 0
        self.b_run.setEnabled(False)
        self.b_site.setEnabled(False)
        self.b_crawl.setEnabled(False)
        self.b_stop.setEnabled(True)
        self.busy.start("Crawling…")
        self.status.setText("Crawling the in-scope site…")
        send = self._make_send()
        oob = self._oob_bridge()
        checks = self._selected_checks()
        px, verify = self.win.proxies(), self.win.verify_tls()
        in_scope = lambda h: bool(h and eng.in_scope(h) is True)   # noqa: E731

        def fetch(url):
            try:
                r = requests.get(url, proxies=px, verify=verify, timeout=15, allow_redirects=True,
                                 headers={"User-Agent": "Mozilla/5.0 Wyrm spider"})
            except requests.RequestException:
                return None
            return {"content_type": r.headers.get("Content-Type", ""), "text": r.text, "final_url": r.url}

        def work():
            from ..security.audit import spider
            reqs = spider.crawl([cur], fetch, in_scope, should_stop=lambda: self._stop_flag)
            # total=0 marks this as a status message, not per-request progress (QA-M2: otherwise it was
            # formatted as a URL -> 'Auditing 0/11 · crawled 11 request(s)…')
            self._progress.emit(0, 0, f"crawled {len(reqs)} request(s) — auditing…")
            if not reqs or self._stop_flag:
                return []
            return engine.scan_site(reqs, send, should_stop=lambda: self._stop_flag,
                                    on_finding=lambda f: self._finding.emit(f), oob=oob, checks=checks,
                                    on_progress=lambda d, n, u: self._progress.emit(d, n, u))
        self.win.runner.run(work, lambda ok, res: self._done.emit(bool(ok), res))

    def _on_progress(self, done, total, url):
        self._last_prog = (done, total, url)
        self._render_progress()

    def _render_progress(self):
        """Render the footer from the last progress + the live finding count (QA-M2: the counter now updates as
        findings stream in, not only once per completed request)."""
        done, total, url = getattr(self, "_last_prog", (0, 0, ""))
        n = getattr(self, "_count", 0)
        if total == 0:   # a status message (e.g. the post-crawl line), not per-request progress
            self.status.setText((url or "Working…") + (f" · {n} issue(s) so far" if n else ""))
        else:
            self.status.setText(f"Auditing {done}/{total} · {url[:70]} · {n} issue(s) so far")

    def _stop(self):
        self._stop_flag = True
        self.b_stop.setEnabled(False)
        self.status.setText("Stopping…")

    # ------------------------------------------------------------ results (UI thread)
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    _SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    def _flush_ui_refresh(self):
        self._render_progress()        # QA-M2: live 'N issue(s) so far' counter
        self._update_add_buttons()     # QA-L3: results now exist

    def _on_finding(self, f):
        self._count = getattr(self, "_count", 0) + 1
        sev = f.get("severity", "info")
        it = QTreeWidgetItem([f.get("title", ""), sev_title(sev), f.get("param", ""), f.get("confidence", "")])
        if sev in SEV_COLOR:
            it.setForeground(1, QBrush(QColor(SEV_COLOR[sev])))
        it.setData(0, Qt.ItemDataRole.UserRole, f)
        rank = self._SEV_RANK.get(sev, 4)
        it.setData(1, Qt.ItemDataRole.UserRole, rank)
        # keep the list ordered most-severe first as findings stream in (stable within a severity)
        pos = self.tree.topLevelItemCount()
        for i in range(self.tree.topLevelItemCount()):
            if (self.tree.topLevelItem(i).data(1, Qt.ItemDataRole.UserRole) or 4) > rank:
                pos = i
                break
        self.tree.insertTopLevelItem(pos, it)
        if self.tree.topLevelItemCount() == 1:
            self.tree.setCurrentItem(it)
        self._ui_refresh.start()   # coalesced footer/button refresh (keeps the UI responsive under a burst)

    def _on_done(self, ok, res):
        self._running = False
        self.busy.stop()
        self.b_run.setEnabled(True)
        self.b_site.setEnabled(True)
        self.b_crawl.setEnabled(True)
        self.b_stop.setEnabled(False)
        self._update_add_buttons()   # flush the final state in case the coalesced refresh was still pending
        n = getattr(self, "_count", 0)
        if not ok:
            self.status.setText(f"Audit failed: {res}")
        else:
            counts: dict[str, int] = {}
            for i in range(self.tree.topLevelItemCount()):
                f = self.tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole) or {}
                s = f.get("severity", "info")
                counts[s] = counts.get(s, 0) + 1
            parts = [f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low", "info") if counts.get(s)]
            summary = ", ".join(parts) if parts else "no issues found"
            self.status.setText(f"Audit complete — {summary} ({n} total). Only test authorized targets.")

    def _show(self, it, _prev=None):
        f = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not f:
            self.detail.clear()
            return
        html = (f"{sev_badge(f.get('severity', 'info'))} <b>{escape(f.get('title', ''))}</b>"
                f"<br><br>{escape(f.get('evidence', ''))}"
                f"<br><br><b>Where:</b> {escape(f.get('loc', ''))} parameter <code>{escape(f.get('param', '') or '—')}</code>"
                f"<br><b>Confidence:</b> {escape(f.get('confidence', ''))} · HTTP {escape(str(f.get('status', '')))}")
        if f.get("payload"):
            html += f"<br><br><b>Payload:</b><br><code>{escape(f['payload'])}</code>"
        remediation, refs = _advice(f.get("check", ""))
        if remediation:
            html += f"<br><br><b>Remediation:</b> {escape(remediation)}"
        if refs:
            html += "<br><b>References:</b><br>" + "<br>".join(f"<a href='{escape(u)}'>{escape(u)}</a>" for u in refs)
        if f.get("url"):
            html += f"<br><br><b>URL:</b> <a href='{escape(f['url'])}'>{escape(f['url'])}</a>"
        self.detail.setHtml(html)

    # ------------------------------------------------------------ findings
    def _finding_to_dialog(self, f):
        sev = f.get("severity") if f.get("severity") in ("critical", "high", "medium", "low", "info") else "info"
        remediation, refs = _advice(f.get("check", ""))
        desc = (f"{f.get('evidence', '')}\n\nWhere: {f.get('loc', '')} parameter {f.get('param', '') or '-'}\n"
                f"Confidence: {f.get('confidence', '')}\nPayload: {f.get('payload', '')}")
        if remediation:
            desc += f"\n\nRemediation: {remediation}"
        if refs:
            desc += "\nReferences:\n" + "\n".join(f"- {u}" for u in refs)
        self.win.add_finding_dialog(title=f.get("title", "Issue"), severity=sev, url=f.get("url", ""), description=desc)

    def _add_finding(self):
        it = self.tree.currentItem()
        f = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not f:
            self.status.setText("Select an issue first.")
            return
        self._finding_to_dialog(f)

    def _add_all(self):
        for i in range(self.tree.topLevelItemCount()):
            f = self.tree.topLevelItem(i).data(0, Qt.ItemDataRole.UserRole)
            if f:
                self._finding_to_dialog(f)


def _as_text(b) -> str:
    if isinstance(b, (bytes, bytearray)):
        return bytes(b).decode("utf-8", "replace")
    return str(b or "")
