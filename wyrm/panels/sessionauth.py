#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/sessionauth.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Session / auth tab: define a login macro and have Wyrm auto re-login when the session expires."""
from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QPlainTextEdit,
                               QPushButton, QVBoxLayout, QWidget)

from ..security import mitm, sessionauth
from .common import mono


class SessionAuthTab(QWidget):
    """Login macro + logged-out rule; the SessionAuth engine runs it inside the proxy."""

    _log = Signal()

    def __init__(self, win):
        super().__init__()
        self.win = win
        self.engine = sessionauth.SessionAuth().load(win.data_dir / "sessionauth.json")
        self.engine.notify = lambda: self._log.emit()
        self._log.connect(self._refresh_log)
        if mitm.ACTIVE is not None:
            self.engine.install(mitm.ACTIVE)

        v = QVBoxLayout(self)
        active = mitm.ACTIVE is not None
        intro = QLabel(
            "<b>Session / auth</b> — define a <b>login macro</b> (one request that logs you in). When a response "
            "looks logged-out (a 401/403, or text you specify), Wyrm re-runs the macro, grabs the fresh session "
            "cookies and injects them into later in-scope requests — so a long scan or Intruder run won't die when "
            "the session expires." + ("" if active else " <br><i>Turn on the intercepting proxy to use this.</i>"))
        intro.setWordWrap(True)
        v.addWidget(intro)

        self.enabled = QCheckBox("Enable session handling")
        self.enabled.setChecked(bool(self.engine.data.get("enabled")))
        self.enabled.toggled.connect(self._toggle)
        v.addWidget(self.enabled)

        macro = QGroupBox("Login macro")
        mg = QVBoxLayout(macro)
        r1 = QHBoxLayout()
        self.method = QComboBox()
        self.method.addItems(["POST", "GET", "PUT"])
        self.method.setCurrentText(self.engine.data["macro"].get("method", "POST"))
        r1.addWidget(self.method)
        self.url = QLineEdit(self.engine.data["macro"].get("url", ""))
        self.url.setPlaceholderText("https://target/login")
        r1.addWidget(self.url, 1)
        mg.addLayout(r1)
        mg.addWidget(QLabel("Headers (one per line, e.g. Content-Type: application/json)"))
        self.headers = mono(QPlainTextEdit())
        self.headers.setPlaceholderText("Content-Type: application/x-www-form-urlencoded")
        self.headers.setMaximumHeight(80)
        self.headers.setPlainText("\n".join(f"{k}: {v}" for k, v in self.engine.data["macro"].get("headers", [])))
        mg.addWidget(self.headers)
        mg.addWidget(QLabel("Body"))
        self.body = mono(QPlainTextEdit())
        self.body.setPlaceholderText("username=admin&password=secret")
        self.body.setMaximumHeight(80)
        self.body.setPlainText(self.engine.data["macro"].get("body", ""))
        mg.addWidget(self.body)
        v.addWidget(macro)

        rule = QGroupBox("When to re-login & where to apply")
        rg = QVBoxLayout(rule)
        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Apply to hosts containing"))
        self.match_hosts = QLineEdit(self.engine.data.get("match_hosts", ""))
        self.match_hosts.setPlaceholderText("(blank = the macro's host)")
        r2.addWidget(self.match_hosts, 1)
        rg.addLayout(r2)
        r3 = QHBoxLayout()
        r3.addWidget(QLabel("Logged-out statuses"))
        self.statuses = QLineEdit(", ".join(str(s) for s in self.engine.data.get("logout_status", [401, 403])))
        r3.addWidget(self.statuses)
        r3.addWidget(QLabel("or body matches"))
        self.regex = QLineEdit(self.engine.data.get("logout_regex", ""))
        self.regex.setPlaceholderText("e.g. (Sign in|session expired)")
        r3.addWidget(self.regex, 1)
        rg.addLayout(r3)
        v.addWidget(rule)

        btns = QHBoxLayout()
        b_save = QPushButton("Save")
        b_save.setObjectName("Primary")
        b_save.clicked.connect(self._save)
        btns.addWidget(b_save)
        b_run = QPushButton("Run macro now")
        b_run.clicked.connect(self._run_now)
        btns.addWidget(b_run)
        b_clear = QPushButton("Clear cookies")
        b_clear.clicked.connect(lambda: (self.engine.clear_cookies()))
        btns.addWidget(b_clear)
        btns.addStretch(1)
        v.addLayout(btns)

        self.status = QLabel("")
        self.status.setObjectName("Muted")
        self.status.setWordWrap(True)
        v.addWidget(self.status)
        self.logview = mono(QPlainTextEdit())
        self.logview.setReadOnly(True)
        self.logview.setMaximumHeight(140)
        v.addWidget(self.logview)
        v.addStretch(1)
        self._refresh_log()

    # -------------------------------------------------- actions
    def _collect(self):
        headers = []
        for line in self.headers.toPlainText().splitlines():
            if ":" in line:
                k, _, val = line.partition(":")
                if k.strip():
                    headers.append([k.strip(), val.strip()])
        statuses = []
        for part in self.statuses.text().replace(";", ",").split(","):
            part = part.strip()
            if part.isdigit():
                statuses.append(int(part))
        self.engine.data["macro"] = {"method": self.method.currentText(), "url": self.url.text().strip(),
                                     "headers": headers, "body": self.body.toPlainText()}
        self.engine.data["match_hosts"] = self.match_hosts.text().strip()
        self.engine.data["logout_status"] = statuses or [401, 403]
        self.engine.data["logout_regex"] = self.regex.text().strip()
        self.engine.data["enabled"] = self.enabled.isChecked()

    def _save(self):
        self._collect()
        self.engine.save()
        self.status.setText("Saved. Session handling is " + ("on." if self.enabled.isChecked() else "off."))

    def _toggle(self, on):
        self.engine.data["enabled"] = on
        self.engine.save()

    def _run_now(self):
        self._collect()
        self.engine.save()
        if not self.engine.data["macro"]["url"]:
            self.status.setText("Enter the login URL first.")
            return
        self.engine.run_now()
        self.status.setText("Running the login macro…")

    def load_macro(self, method, url, headers: dict, body: str):
        """Populate the macro from a captured request (used by 'Send to Session macro')."""
        self.method.setCurrentText(method if method in ("POST", "GET", "PUT") else "POST")
        self.url.setText(url)
        self.headers.setPlainText("\n".join(f"{k}: {v}" for k, v in (headers or {}).items()))
        self.body.setPlainText(body or "")
        self.status.setText("Loaded request into the login macro. Review it, then Save and enable.")

    def _refresh_log(self):
        self.status.setText(f"Held session cookies: {len(self.engine.cookies)}"
                            + (f" ({', '.join(list(self.engine.cookies)[:6])})" if self.engine.cookies else ""))
        self.logview.setPlainText("\n".join(self.engine.log[-100:]))
        self.logview.verticalScrollBar().setValue(self.logview.verticalScrollBar().maximum())
