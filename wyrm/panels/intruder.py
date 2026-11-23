#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/intruder.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Security panel → Intruder: scope-gated, rate-limited payload testing."""
from __future__ import annotations

from html import escape
from urllib.parse import urlparse

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import QComboBox, QDoubleSpinBox, QFileDialog, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox, QSplitter, QTreeWidget, QVBoxLayout, QWidget

from .common import STATUS_COLOR, _SortItem, _pane, mono
from ..security import fuzzer, tools


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
            add = QPushButton("Add ▾")
            add.setObjectName("Segment")
            add.setFixedHeight(24)
            from ..security import payloads as _pl
            menu = QMenu(add)
            menu.addAction("Numbers…", self._add_numbers)
            menu.addSeparator()
            for name in _pl.LISTS:
                menu.addAction(name, lambda _c=False, n=name: self._add_list(n))
            add.setMenu(menu)
            head.addWidget(add)
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

    def load_request(self, method: str, url: str, headers: dict, body: str = ""):
        """Fill Intruder from another tool (Traffic, Intercept). Mark what to fuzz with §…§ (e.g. select a value
        and press the §-button), then Start."""
        self.method.setCurrentText(method or "GET")
        self.url.setText(url)
        lines = [f"{k}: {v}" for k, v in headers.items() if k.lower() not in ("content-length", "host")]
        self.headers.setPlainText("\n".join(lines))
        self.body.setPlainText(body or "")

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

    def _append_payloads(self, lines):
        if not lines:
            return
        cur = self.payloads.toPlainText()
        prefix = cur + ("\n" if cur and not cur.endswith("\n") else "")
        self.payloads.setPlainText(prefix + "\n".join(lines))

    def _add_list(self, name):
        from ..security import payloads as _pl
        self._append_payloads(_pl.LISTS.get(name, []))

    def _add_numbers(self):
        from PySide6.QtWidgets import QInputDialog
        from ..security import payloads as _pl
        txt, ok = QInputDialog.getText(self, "Number payloads",
                                       "Range as from,to[,step] (e.g. 1,100 or 0,1000,10):")
        if not ok or not txt.strip():
            return
        parts = [p.strip() for p in txt.replace("-", ",").split(",") if p.strip() != ""]
        try:
            a, b = int(parts[0]), int(parts[1])
            step = int(parts[2]) if len(parts) > 2 else 1
        except (ValueError, IndexError):
            QMessageBox.information(self, "Number payloads", "Enter a range like 1,100 or 0,1000,10.")
            return
        self._append_payloads(_pl.numbers(a, b, step)[:5000])   # cap to keep the list manageable

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
                self._highlight_outliers()
            else:
                self.summary.setText(f"Failed: {res}")
                QMessageBox.warning(self, "Intruder", f"Attack failed:\n{res}")
        self.win.runner.run(worker, finished)

    def _highlight_outliers(self):
        """After an attack, bold the rows whose response length or status differs from the common value —
        that's usually where the interesting payload landed (a different page, an error, a successful login)."""
        from collections import Counter
        from PySide6.QtGui import QFont
        rows = [self.table.topLevelItem(i) for i in range(self.table.topLevelItemCount())]
        if len(rows) < 4:
            return
        lengths, statuses = Counter(), Counter()
        for it in rows:
            r = it.data(0, Qt.ItemDataRole.UserRole) or {}
            lengths[r.get("length")] += 1
            statuses[r.get("status")] += 1
        modal_len = lengths.most_common(1)[0][0]
        modal_status = statuses.most_common(1)[0][0]
        n_out = 0
        for it in rows:
            r = it.data(0, Qt.ItemDataRole.UserRole) or {}
            len_out = r.get("length") != modal_len
            stat_out = r.get("status") != modal_status
            if len_out or stat_out:
                n_out += 1
                f = it.font(0)
                f.setBold(True)
                for c in range(it.columnCount()):
                    it.setFont(c, f)
                if len_out:
                    it.setForeground(3, QBrush(QColor("#f0883e")))
        if n_out:
            self.summary.setText(self.summary.text() + f" · {n_out} stand out (length/status differs)")

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
