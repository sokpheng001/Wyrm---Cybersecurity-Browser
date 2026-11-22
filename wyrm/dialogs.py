#------------------------------------------------------------------------------
# Wyrm — wyrm/dialogs.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Dialogs: engagement editor, finding editor, settings (proxy)."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QSpinBox, QVBoxLayout, QWidget,
)

from .security.store import SEVERITIES, Engagement


class EngagementDialog(QDialog):
    def __init__(self, parent=None, engagement: Engagement | None = None):
        super().__init__(parent)
        self.setWindowTitle("Edit engagement" if engagement and engagement.id else "New engagement")
        self.setMinimumWidth(520)
        self.e = engagement or Engagement(0, "")
        v = QVBoxLayout(self)
        intro = QLabel("An engagement keeps cookies, logins and findings for one authorized target separate from "
                       "everything else. Active features (JS fetching, repeater, recon) only run against in-scope hosts.")
        intro.setWordWrap(True)
        intro.setStyleSheet("color: gray")
        v.addWidget(intro)
        f = QFormLayout()
        self.name = QLineEdit(self.e.name)
        self.name.setPlaceholderText("e.g. ACME bug bounty, Client X web app pentest")
        f.addRow("Name", self.name)
        self.scope = QPlainTextEdit("\n".join(self.e.scope))
        self.scope.setPlaceholderText("One per line:\nexample.com\n*.example.com\n10.0.0.0/24\n!admin.example.com   (exclude)")
        self.scope.setMinimumHeight(120)
        f.addRow("Scope", self.scope)
        self.block = QCheckBox("Block requests to out-of-scope hosts (strict mode; may break third-party assets)")
        self.block.setChecked(self.e.block_out_of_scope)
        f.addRow("", self.block)
        self.notes = QPlainTextEdit(self.e.notes)
        self.notes.setPlaceholderText("Program rules, test accounts, out-of-scope vulnerability types, contacts…")
        self.notes.setMaximumHeight(90)
        f.addRow("Notes", self.notes)
        v.addLayout(f)
        self.auth = QCheckBox("I have written authorization to test the targets in this scope")
        self.auth.setChecked(bool(self.e.id))
        v.addWidget(self.auth)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        v.addWidget(bb)

    def _accept(self):
        scope = [s.strip() for s in self.scope.toPlainText().splitlines() if s.strip()]
        if not self.name.text().strip() or not scope:
            QMessageBox.warning(self, "Engagement", "Give the engagement a name and at least one in-scope target.")
            return
        if not self.auth.isChecked():
            QMessageBox.warning(self, "Authorization required",
                                "Only test systems you own or have explicit written permission to test.")
            return
        self.e.name = self.name.text().strip()
        self.e.scope = scope
        self.e.block_out_of_scope = self.block.isChecked()
        self.e.notes = self.notes.toPlainText().strip()
        self.accept()


class FindingDialog(QDialog):
    def __init__(self, parent=None, title="", severity="medium", url="", description="", evidence="",
                 can_screenshot=True, edit=False):
        super().__init__(parent)
        self.setWindowTitle("Edit finding" if edit else "Add finding")
        self.setMinimumWidth(560)
        f = QFormLayout(self)
        self.title = QLineEdit(title)
        f.addRow("Title", self.title)
        self.sev = QComboBox()
        self.sev.addItems([s.title() for s in SEVERITIES])
        self.sev.setCurrentIndex(SEVERITIES.index(severity) if severity in SEVERITIES else 2)
        f.addRow("Severity", self.sev)
        self.url = QLineEdit(url)
        f.addRow("URL", self.url)
        self.desc = QPlainTextEdit(description)
        self.desc.setPlaceholderText("What is the issue, how to reproduce, impact, recommended fix")
        f.addRow("Description", self.desc)
        self.evidence = QPlainTextEdit(evidence)
        self.evidence.setPlaceholderText("Request/response, headers, payload output…")
        self.evidence.setMaximumHeight(120)
        f.addRow("Evidence", self.evidence)
        self.shot = QCheckBox("Attach a screenshot of the current page")
        self.shot.setChecked(can_screenshot and not edit)
        self.shot.setVisible(can_screenshot and not edit)
        f.addRow("", self.shot)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(lambda: self.title.text().strip() and self.accept())
        bb.rejected.connect(self.reject)
        f.addRow(bb)

    def values(self) -> dict:
        return {"title": self.title.text().strip(), "severity": SEVERITIES[self.sev.currentIndex()],
                "url": self.url.text().strip(), "description": self.desc.toPlainText().strip(),
                "evidence": self.evidence.toPlainText().strip()}


class SettingsDialog(QDialog):
    """Full browser settings: General, Privacy & Security, Network (proxy)."""

    def __init__(self, win, parent=None):
        super().__init__(parent or win)
        self.win = win
        self.settings = win.settings
        self.setWindowTitle("Settings")
        self.setMinimumSize(560, 520)
        from PySide6.QtWidgets import QTabWidget
        root = QVBoxLayout(self)
        tabs = QTabWidget()
        tabs.addTab(self._general(), "General")
        tabs.addTab(self._privacy(), "Privacy & Security")
        tabs.addTab(self._network(), "Network")
        root.addWidget(tabs)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._save)
        bb.rejected.connect(self.reject)
        root.addWidget(bb)

    # ----------------------------------------------------- General
    def _general(self):
        from . import engines
        w = QWidget()
        f = QFormLayout(w)
        self.engine = QComboBox()
        for key, e in engines.ENGINES.items():
            self.engine.addItem(e.name, key)
        self.engine.setCurrentIndex(max(0, self.engine.findData(self.settings.value("search/engine", engines.DEFAULT_ENGINE))))
        f.addRow("Default search engine", self.engine)
        self.theme = QComboBox()
        for key, label in (("system", "Follow system"), ("dark", "Dark"), ("light", "Light"),
                           ("hacker", "Hacker (pro dark)")):
            self.theme.addItem(label, key)
        self.theme.setCurrentIndex(max(0, self.theme.findData(self.settings.value("theme", "system"))))
        f.addRow("Theme", self.theme)
        self.restore_tabs = QCheckBox("Reopen last session's tabs on startup")
        self.restore_tabs.setChecked(self.settings.value("general/restore_tabs", False, type=bool))
        f.addRow("", self.restore_tabs)
        self.autoanalyze = QCheckBox("Auto-analyze in-scope pages (security grade)")
        self.autoanalyze.setChecked(self.settings.value("sec/auto", True, type=bool))
        f.addRow("", self.autoanalyze)
        note = QLabel("Downloads are saved to your system Downloads folder.")
        note.setObjectName("Muted")
        f.addRow("", note)
        # AI Triage (optional) — user's own LLM API key, used only for the scope-gated triage assistant
        f.addRow(QLabel("<b>AI Triage</b>"))
        self.ai_key = QLineEdit(self.settings.value("ai/api_key", "", type=str))
        self.ai_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.ai_key.setPlaceholderText("API key (kept only on this device)")
        f.addRow("API key", self.ai_key)
        self.ai_model = QLineEdit(self.settings.value("ai/model", "kim-modeling-sp-001", type=str))
        f.addRow("Model", self.ai_model)
        ai_note = QLabel("Powers the human-in-the-loop AI Triage tool (Tools → AI Triage). Non-destructive, "
                         "scope-gated. Leave blank to disable.")
        ai_note.setObjectName("Muted")
        ai_note.setWordWrap(True)
        f.addRow("", ai_note)
        return w

    # ----------------------------------------------------- Privacy & Security
    def _privacy(self):
        w = QWidget()
        f = QFormLayout(w)
        self.https_only = QCheckBox("HTTPS-Only mode — upgrade every connection to HTTPS")
        self.https_only.setChecked(self.settings.value("privacy/https_only", True, type=bool))
        f.addRow("Encryption", self.https_only)
        self.doh_mode = QComboBox()
        for key, label in (("secure", "On (fallback to system DNS)"), ("strict", "Strict (encrypted only)"), ("off", "Off")):
            self.doh_mode.addItem(label, key)
        self.doh_mode.setCurrentIndex(max(0, self.doh_mode.findData(self.settings.value("privacy/doh_mode", "secure"))))
        f.addRow("Encrypted DNS (DoH)", self.doh_mode)
        self.doh_prov = QComboBox()
        for key, (label, _u) in self.win.DOH.items():
            self.doh_prov.addItem(label, key)
        self.doh_prov.setCurrentIndex(max(0, self.doh_prov.findData(self.settings.value("privacy/doh_provider", "cloudflare"))))
        f.addRow("DNS provider", self.doh_prov)
        for key, label in (("ads", "Block ads"), ("trackers", "Block trackers"),
                           ("malware", "Block malware & phishing sites"), ("linkguard", "Smart Link Check"),
                           ("antifp", "Resist fingerprinting"), ("popups", "Block ad pop-ups"),
                           ("params", "Strip tracking parameters"), ("youtube", "Remove YouTube ads")):
            cb = QCheckBox(label)
            cb.setChecked(self.settings.value(f"shields/{key}", True, type=bool))
            setattr(self, f"sh_{key}", cb)
            f.addRow("Shields" if key == "ads" else "", cb)
        return w

    # ----------------------------------------------------- Network (proxy)
    def _network(self):
        w = QWidget()
        f = QFormLayout(w)
        info = QLabel("Route all browser traffic through an intercepting proxy such as Burp Suite or OWASP ZAP. "
                      "Proxy changes apply after a restart.")
        info.setWordWrap(True)
        info.setObjectName("Muted")
        f.addRow(info)
        self.proxy_enabled = QCheckBox("Use an upstream proxy")
        self.proxy_enabled.setChecked(self.settings.value("proxy/enabled", False, type=bool))
        f.addRow("", self.proxy_enabled)
        self.proxy_host = QLineEdit(self.settings.value("proxy/host", "127.0.0.1"))
        f.addRow("Host", self.proxy_host)
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(self.settings.value("proxy/port", 8080, type=int))
        f.addRow("Port", self.proxy_port)
        self.proxy_insecure = QCheckBox("Trust the proxy's CA (ignore certificate errors while proxied)")
        self.proxy_insecure.setChecked(self.settings.value("proxy/insecure", True, type=bool))
        f.addRow("", self.proxy_insecure)
        return w

    def _save(self):
        s = self.settings
        s.setValue("search/engine", self.engine.currentData())
        s.setValue("general/restore_tabs", self.restore_tabs.isChecked())
        s.setValue("sec/auto", self.autoanalyze.isChecked())
        s.setValue("ai/api_key", self.ai_key.text().strip())
        s.setValue("ai/model", self.ai_model.text().strip() or "kim-modeling-sp-001")
        s.setValue("privacy/https_only", self.https_only.isChecked())
        s.setValue("privacy/doh_mode", self.doh_mode.currentData())
        s.setValue("privacy/doh_provider", self.doh_prov.currentData())
        for key in ("ads", "trackers", "malware", "linkguard", "antifp", "popups", "params", "youtube"):
            s.setValue(f"shields/{key}", getattr(self, f"sh_{key}").isChecked())
        proxy_before = (s.value("proxy/enabled", False, type=bool), s.value("proxy/host", ""), s.value("proxy/port", 0, type=int),
                        s.value("proxy/insecure", True, type=bool))
        s.setValue("proxy/enabled", self.proxy_enabled.isChecked())
        s.setValue("proxy/host", self.proxy_host.text().strip() or "127.0.0.1")
        s.setValue("proxy/port", self.proxy_port.value())
        s.setValue("proxy/insecure", self.proxy_insecure.isChecked())
        proxy_after = (self.proxy_enabled.isChecked(), s.value("proxy/host", ""), self.proxy_port.value(),
                       self.proxy_insecure.isChecked())
        # apply live where possible
        self.win.engine_box.setCurrentIndex(max(0, self.win.engine_box.findData(self.engine.currentData())))
        self.win.apply_theme(self.theme.currentData())
        self.win.apply_dns()
        if hasattr(self.win.security, "shields"):
            self.win.security.shields.sync_from_settings()
        self.accept()
        if proxy_before != proxy_after:
            self.win.prompt_restart_for_proxy()
