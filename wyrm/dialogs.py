"""Dialogs: engagement editor, finding editor, settings (proxy)."""
from __future__ import annotations

from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel, QLineEdit, QMessageBox, QPlainTextEdit,
    QSpinBox, QVBoxLayout,
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
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("Settings: proxy")
        self.setMinimumWidth(460)
        f = QFormLayout(self)
        info = QLabel("Route all browser traffic through an intercepting proxy such as Burp Suite or OWASP ZAP. "
                      "The browser restarts to apply changes.")
        info.setWordWrap(True)
        f.addRow(info)
        self.enabled = QCheckBox("Use proxy")
        self.enabled.setChecked(settings.value("proxy/enabled", False, type=bool))
        f.addRow(self.enabled)
        self.host = QLineEdit(settings.value("proxy/host", "127.0.0.1"))
        f.addRow("Host", self.host)
        self.port = QSpinBox()
        self.port.setRange(1, 65535)
        self.port.setValue(settings.value("proxy/port", 8080, type=int))
        f.addRow("Port", self.port)
        self.insecure = QCheckBox("Trust the proxy's CA (ignore certificate errors while proxied)")
        self.insecure.setToolTip("Needed for Burp/ZAP HTTPS interception unless you install their CA certificate.")
        self.insecure.setChecked(settings.value("proxy/insecure", True, type=bool))
        f.addRow(self.insecure)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._save)
        bb.rejected.connect(self.reject)
        f.addRow(bb)

    def _save(self):
        s = self.settings
        s.setValue("proxy/enabled", self.enabled.isChecked())
        s.setValue("proxy/host", self.host.text().strip() or "127.0.0.1")
        s.setValue("proxy/port", self.port.value())
        s.setValue("proxy/insecure", self.insecure.isChecked())
        self.accept()
