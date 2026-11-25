#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/tools.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Security panel → Tools: Decoder, JWT, Hash, Repeater, Match & Replace, Comparer, Sequencer, AI Triage."""
from __future__ import annotations

import json
from html import escape
from urllib.parse import urlparse

from PySide6.QtCore import QTimer, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QStackedWidget, QTabBar, QTextBrowser, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget

from .common import HeaderHighlighter, _format_response, _pane, mono
from ..security import tools
from ..widgets import BusyOverlay


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
        from ..security import triage
        eng = self.win.engagement
        scope = ", ".join(eng.scope) if eng and eng.scope else ""
        self.tr_scope.setText(f"Authorized scope: <b>{escape(scope) or 'none set — set an engagement scope first'}</b> · "
                              "analysis only, no requests are sent, benign verification steps only.")
        from .. import secretstore
        key = secretstore.get(self.win.settings, "ai/api_key")
        model = (self.win.settings.value("ai/model", "", type=str) or triage.DEFAULT_MODEL)
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
                status = getattr(r, "status", None)
                head = (f"HTTP {status}" if status else "Couldn't reach the AI endpoint") if status is not None \
                    else "Triage failed"
                reason = getattr(r, "reason", None) or str(r) or type(r).__name__
                self.tr_out.setHtml(f"<p style='color:#da1e28'><b>{escape(head)}</b> — {escape(reason)}</p>"
                                    "<p style='color:#8d8d8d'>Check Settings → AI (Test connection).</p>")
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
        self.r_preview = None  # web view created on first Preview click (keeps startup fast)
        self.r_resp_stack = QStackedWidget()
        self.r_resp_stack.addWidget(self.r_resp)
        self.r_busy = BusyOverlay(self.r_resp_stack)
        # Preview: spinner while the HTML (and its images/CSS) renders; a timer stops it if a resource hangs
        self._preview_timeout = QTimer(self, singleShot=True, interval=15000)
        self._preview_timeout.timeout.connect(self._preview_done)
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
        scan = QPushButton("Active scan")
        scan.setToolTip("Audit this request for XSS / SQLi / SSTI / traversal / open redirect / CRLF (in-scope only)")
        scan.clicked.connect(lambda: self.win.security.audit.scan_request(
            self.r_method.currentText(), self.r_url.text(), tools.parse_headers(self.r_headers.toPlainText()),
            self.r_body.toPlainText()))
        row2.addWidget(scan)
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
        from ..security.rewrite import Rule
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
        from ..security.rewrite import Rule
        idx = item.data(0, Qt.ItemDataRole.UserRole)
        if idx is None or idx >= len(self.win.rules.rules):
            return
        r: Rule = self.win.rules.rules[idx]
        r.enabled = item.checkState(0) == Qt.CheckState.Checked
        r.name, r.host_glob, r.header, r.match, r.replace = (item.text(i) for i in range(1, 6))
        self.win.save_rules()

    def _rw_add(self):
        from ..security.rewrite import Rule
        self.win.rules.rules.append(Rule(True, "New rule", "*", "User-Agent", "", "Wyrm/1.0"))
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

    def compare_add(self, text: str):
        """Send a request/response into the Comparer (fills A first, then B)."""
        self._select_tool("Comparer")
        if not self.cmp_a.toPlainText().strip():
            self.cmp_a.setPlainText(text)
        else:
            self.cmp_b.setPlainText(text)

    def load_request(self, method, url, headers: dict, body: str = ""):
        self._select_tool("Repeater")
        # open each sent request in its own tab so earlier ones are never lost
        self._r_new_session(method or "GET", url, "\n".join(f"{k}: {v}" for k, v in headers.items()), body or "")
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
            if self.r_preview is None:
                from PySide6.QtWebEngineWidgets import QWebEngineView
                from PySide6.QtWebEngineCore import QWebEngineSettings
                self.r_preview = QWebEngineView()
                self.r_preview.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, False)
                self.r_preview.loadFinished.connect(self._preview_done)
                self.r_resp_stack.addWidget(self.r_preview)
            self.r_resp_stack.setCurrentWidget(self.r_preview)
            body = getattr(self, "_last_body", "")
            if body:
                self._previewing = True
                self.r_busy.start("Rendering preview…")
                self._preview_timeout.start()
            self.r_preview.setHtml(body or "<p style='color:gray'>No response yet.</p>")
        else:
            self._preview_done()
            self.r_resp_stack.setCurrentWidget(self.r_resp)

    def _preview_done(self, *_):
        # only our own spinner: never hide the "Sending request…" one
        if getattr(self, "_previewing", False):
            self._previewing = False
            self._preview_timeout.stop()
            self.r_busy.stop()
