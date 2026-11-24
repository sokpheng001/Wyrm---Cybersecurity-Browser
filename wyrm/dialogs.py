#------------------------------------------------------------------------------
# Wyrm — wyrm/dialogs.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Dialogs: engagement editor, finding editor, settings (proxy)."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QFrame, QHBoxLayout, QLabel, QLineEdit,
    QListWidget, QMessageBox, QPlainTextEdit, QPushButton, QScrollArea, QSpinBox, QStackedWidget, QVBoxLayout,
    QWidget,
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
    """Full browser settings with a left sidebar and a search box (type to find any setting)."""

    def __init__(self, win, parent=None):
        super().__init__(parent or win)
        self.win = win
        self.settings = win.settings
        self.setWindowTitle("Settings")
        self.setMinimumSize(620, 460)
        self.resize(860, 640)
        self._rows: list[tuple] = []       # (page_idx, row_widget, search_text, section_header_or_None)
        self._sections: list[tuple] = []   # (page_idx, header_widget)
        root = QVBoxLayout(self)
        # search box — find any setting fast
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search settings…  (e.g. proxy, theme, DNS, downloads, location)")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._do_search)
        root.addWidget(self.search)
        body = QHBoxLayout()
        self.nav = QListWidget(objectName="SettingsNav")
        self.nav.setFixedWidth(168)
        self.stack = QStackedWidget()
        self.nav.currentRowChanged.connect(self._nav_changed)
        body.addWidget(self.nav)
        body.addWidget(self.stack, 1)
        root.addLayout(body, 1)
        for title, builder in (("General", self._general), ("Privacy & Security", self._privacy),
                               ("Network", self._network)):
            self._cur_page = self.stack.count()
            self._cur_section = None
            page = builder()
            sa = QScrollArea()
            sa.setWidgetResizable(True)
            sa.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)  # never scroll sideways
            sa.setFrameShape(QFrame.Shape.NoFrame)
            sa.setWidget(page)
            self.stack.addWidget(sa)
            self.nav.addItem(title)
        self.nav.setCurrentRow(0)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        bb.accepted.connect(self._save)
        bb.rejected.connect(self.reject)
        root.addWidget(bb)

    # ---- page-building helpers (each row is registered so the search box can show/hide it) ----
    def _page(self):
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(10, 8, 10, 10)
        lay.setSpacing(6)
        return page, lay

    def _section(self, lay, title):
        hw = QLabel(f"<b>{title}</b>")
        hw.setContentsMargins(0, 10, 0, 0)
        lay.addWidget(hw)
        self._cur_section = hw
        self._sections.append((self._cur_page, hw))

    def _row(self, lay, label, widget, extra=""):
        rw = QWidget()
        h = QHBoxLayout(rw)
        h.setContentsMargins(0, 2, 0, 2)
        h.setSpacing(10)
        if label:
            lb = QLabel(label)
            lb.setFixedWidth(150)
            lb.setWordWrap(True)
            h.addWidget(lb, 0, Qt.AlignmentFlag.AlignVCenter)
        # keep simple controls a tidy width instead of stretching across the whole dialog (less empty feel)
        if isinstance(widget, (QComboBox, QLineEdit, QSpinBox)):
            widget.setMaximumWidth(360)
        h.addWidget(widget, 1)
        lay.addWidget(rw)
        terms = f"{label} {extra}"
        if isinstance(widget, QCheckBox):
            terms += " " + widget.text()
        self._rows.append((self._cur_page, rw, terms.lower(), self._cur_section))
        return rw

    def _note(self, lay, text):
        lb = QLabel(text)
        lb.setObjectName("Muted")
        lb.setWordWrap(True)
        lay.addWidget(lb)
        self._rows.append((self._cur_page, lb, text.lower(), self._cur_section))

    def _nav_changed(self, i):
        if i >= 0:
            self.stack.setCurrentIndex(i)

    def _do_search(self, text):
        q = text.lower().strip()
        titles = [self.nav.item(i).text().lower() for i in range(self.nav.count())]
        title_hit = [bool(q) and q in t for t in titles]
        page_has = [not q or title_hit[i] for i in range(self.stack.count())]
        sec_hit: dict = {}
        for pidx, rw, terms, sec in self._rows:
            m = (not q) or title_hit[pidx] or (q in terms)
            rw.setVisible(m)
            if m:
                page_has[pidx] = True
                if sec is not None:
                    sec_hit[sec] = True
        for pidx, hw in self._sections:
            hw.setVisible((not q) or title_hit[pidx] or sec_hit.get(hw, False))
        for i in range(self.nav.count()):
            self.nav.item(i).setHidden(bool(q) and not page_has[i])
        if q and (self.nav.currentRow() < 0 or not page_has[self.nav.currentRow()]):
            for i in range(self.stack.count()):
                if page_has[i]:
                    self.nav.setCurrentRow(i)
                    break

    # ----------------------------------------------------- General
    def _general(self):
        from . import engines
        page, lay = self._page()
        self.engine = QComboBox()
        for key, e in engines.ENGINES.items():
            self.engine.addItem(e.name, key)
        self.engine.setCurrentIndex(max(0, self.engine.findData(self.settings.value("search/engine", engines.DEFAULT_ENGINE))))
        self._row(lay, "Default search engine", self.engine, "search provider query")
        self.theme = QComboBox()
        for key, label in (("system", "Follow system"), ("dark", "Dark"), ("light", "Light"),
                           ("hacker", "Hacker (pro dark)")):
            self.theme.addItem(label, key)
        self.theme.setCurrentIndex(max(0, self.theme.findData(self.settings.value("theme", "system"))))
        self._row(lay, "Theme", self.theme, "appearance dark light colour")
        self.restore_tabs = QCheckBox("Reopen last session's tabs on startup")
        self.restore_tabs.setChecked(self.settings.value("general/restore_tabs", False, type=bool))
        self._row(lay, "", self.restore_tabs, "startup session restore")
        self.autoanalyze = QCheckBox("Auto-analyze in-scope pages (security grade)")
        self.autoanalyze.setChecked(self.settings.value("sec/auto", True, type=bool))
        self._row(lay, "", self.autoanalyze, "analysis grade")
        self._section(lay, "Downloads")
        from PySide6.QtCore import QStandardPaths
        self.dl_ask = QCheckBox("Ask where to save each file")
        self.dl_ask.setChecked(self.settings.value("downloads/ask", True, type=bool))
        self._row(lay, "", self.dl_ask, "download save prompt")
        default_dir = self.settings.value("downloads/folder", "", type=str) \
            or QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
        self.dl_folder = QLineEdit(default_dir)
        self.dl_folder.setReadOnly(True)
        browse = QPushButton("Change…")
        browse.clicked.connect(self._pick_download_folder)
        dl_row = QWidget()
        dl_h = QHBoxLayout(dl_row)
        dl_h.setContentsMargins(0, 0, 0, 0)
        dl_h.addWidget(self.dl_folder, 1)
        dl_h.addWidget(browse)
        self._row(lay, "Save files to", dl_row, "download folder location")
        self._note(lay, "When “Ask where to save” is off, files go straight to this folder.")
        self._section(lay, "AI Triage")
        self.ai_key = QLineEdit(self.settings.value("ai/api_key", "", type=str))
        self.ai_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.ai_key.setPlaceholderText("API key (kept only on this device)")
        self._row(lay, "API key", self.ai_key, "ai triage llm key")
        self.ai_model = QLineEdit(self.settings.value("ai/model", "kim-modeling-sp-001", type=str))
        self._row(lay, "Model", self.ai_model, "ai triage llm model")
        self._note(lay, "Powers the human-in-the-loop AI Triage tool (Tools → AI Triage). Non-destructive, "
                        "scope-gated. Leave blank to disable.")
        lay.addStretch(1)
        return page

    # ----------------------------------------------------- Privacy & Security
    def _privacy(self):
        page, lay = self._page()
        self.https_only = QCheckBox("HTTPS-Only mode — upgrade every connection to HTTPS")
        self.https_only.setChecked(self.settings.value("privacy/https_only", True, type=bool))
        self._row(lay, "Encryption", self.https_only, "https tls secure")
        self.doh_mode = QComboBox()
        for key, label in (("secure", "On (fallback to system DNS)"), ("strict", "Strict (encrypted only)"), ("off", "Off")):
            self.doh_mode.addItem(label, key)
        self.doh_mode.setCurrentIndex(max(0, self.doh_mode.findData(self.settings.value("privacy/doh_mode", "secure"))))
        self._row(lay, "Encrypted DNS (DoH)", self.doh_mode, "dns doh resolver")
        self.doh_prov = QComboBox()
        for key, (label, _u) in self.win.DOH.items():
            self.doh_prov.addItem(label, key)
        self.doh_prov.setCurrentIndex(max(0, self.doh_prov.findData(self.settings.value("privacy/doh_provider", "cloudflare"))))
        self._row(lay, "DNS provider", self.doh_prov, "dns provider cloudflare")
        self._section(lay, "Shields")
        for key, label in (("ads", "Block ads"), ("trackers", "Block trackers"),
                           ("malware", "Block malware & phishing sites"), ("linkguard", "Smart Link Check"),
                           ("antifp", "Resist fingerprinting"), ("popups", "Block ad pop-ups"),
                           ("params", "Strip tracking parameters"), ("youtube", "Remove YouTube ads")):
            cb = QCheckBox(label)
            cb.setChecked(self.settings.value(f"shields/{key}", True, type=bool))
            setattr(self, f"sh_{key}", cb)
            self._row(lay, "", cb, "shields block privacy")
        self._section(lay, "Intercepting proxy")
        self._note(lay, "Capture full HTTPS requests and responses (with bodies) and edit responses, in Security "
                        "panel → Proxy. It installs a local certificate and restarts Wyrm. Developers: Kwan, Oda.")
        self._section(lay, "Location")
        self.geo_mode = QComboBox()
        for key, label in (("off", "Normal — let sites ask for my real location"),
                           ("hide", "Hide my location — deny every request (disappear)"),
                           ("custom", "Show a chosen location (appear elsewhere)")):
            self.geo_mode.addItem(label, key)
        cur = self.settings.value("privacy/geo_mode", "", type=str)
        if not cur:
            cur = "custom" if self.settings.value("privacy/geo_spoof", False, type=bool) else "off"
        self.geo_mode.setCurrentIndex(max(0, self.geo_mode.findData(cur)))
        self._row(lay, "Location mode", self.geo_mode, "geolocation spoof hide gps")
        self.geo_lat = QLineEdit(str(self.settings.value("privacy/geo_lat", "", type=str)))
        self.geo_lat.setPlaceholderText("Latitude e.g. 37.5665")
        self.geo_lon = QLineEdit(str(self.settings.value("privacy/geo_lon", "", type=str)))
        self.geo_lon.setPlaceholderText("Longitude e.g. 126.9780")
        use_ip = QPushButton("Use my IP location")
        use_ip.clicked.connect(self._fill_ip_location)
        geo_row = QWidget()
        gh = QHBoxLayout(geo_row)
        gh.setContentsMargins(0, 0, 0, 0)
        gh.addWidget(self.geo_lat)
        gh.addWidget(self.geo_lon)
        gh.addWidget(use_ip)
        self._row(lay, "Coordinates", geo_row, "geolocation latitude longitude")
        self._note(lay, "A VPN or Tor only changes your IP; this also makes sites that ask for your location see "
                        "the place you choose. Takes effect on new page loads.")
        lay.addStretch(1)
        return page

    def _fill_ip_location(self):
        from . import homeinfo
        info = homeinfo.fetch(self.win.proxies(), self.win.verify_tls())
        if info and info.get("lat") is not None:
            self.geo_lat.setText(str(info["lat"]))
            self.geo_lon.setText(str(info["lon"]))
            self.geo_mode.setCurrentIndex(max(0, self.geo_mode.findData("custom")))
        else:
            self.geo_lat.setPlaceholderText("Couldn't fetch — enter manually")

    # ----------------------------------------------------- Network (proxy)
    def _network(self):
        page, lay = self._page()
        self._note(lay, "Route all browser traffic through an intercepting proxy such as Burp Suite or OWASP ZAP. "
                        "Proxy changes apply after a restart.")
        self.proxy_enabled = QCheckBox("Use an upstream proxy")
        self.proxy_enabled.setChecked(self.settings.value("proxy/enabled", False, type=bool))
        self._row(lay, "", self.proxy_enabled, "proxy burp zap upstream")
        self.proxy_host = QLineEdit(self.settings.value("proxy/host", "127.0.0.1"))
        self._row(lay, "Host", self.proxy_host, "proxy host address")
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(self.settings.value("proxy/port", 8080, type=int))
        self._row(lay, "Port", self.proxy_port, "proxy port")
        self.proxy_insecure = QCheckBox("Trust the proxy's CA (ignore certificate errors while proxied)")
        self.proxy_insecure.setChecked(self.settings.value("proxy/insecure", False, type=bool))
        self._row(lay, "", self.proxy_insecure, "proxy certificate ca insecure")
        lay.addStretch(1)
        return page

    def _pick_download_folder(self):
        from PySide6.QtWidgets import QFileDialog
        d = QFileDialog.getExistingDirectory(self, "Choose download folder", self.dl_folder.text())
        if d:
            self.dl_folder.setText(d)

    def _save(self):
        s = self.settings
        s.setValue("search/engine", self.engine.currentData())
        s.setValue("downloads/ask", self.dl_ask.isChecked())
        s.setValue("downloads/folder", self.dl_folder.text())
        s.setValue("general/restore_tabs", self.restore_tabs.isChecked())
        s.setValue("sec/auto", self.autoanalyze.isChecked())
        s.setValue("ai/api_key", self.ai_key.text().strip())
        s.setValue("ai/model", self.ai_model.text().strip() or "kim-modeling-sp-001")
        s.setValue("privacy/https_only", self.https_only.isChecked())
        s.setValue("privacy/geo_mode", self.geo_mode.currentData())
        s.setValue("privacy/geo_lat", self.geo_lat.text().strip())
        s.setValue("privacy/geo_lon", self.geo_lon.text().strip())
        s.setValue("privacy/doh_mode", self.doh_mode.currentData())
        s.setValue("privacy/doh_provider", self.doh_prov.currentData())
        for key in ("ads", "trackers", "malware", "linkguard", "antifp", "popups", "params", "youtube"):
            s.setValue(f"shields/{key}", getattr(self, f"sh_{key}").isChecked())
        proxy_before = (s.value("proxy/enabled", False, type=bool), s.value("proxy/host", ""), s.value("proxy/port", 0, type=int),
                        s.value("proxy/insecure", False, type=bool))
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
        self.win._apply_fp_ua_all()   # apply/clear the anti-fingerprinting User-Agent without a restart
        self.accept()
        if proxy_before != proxy_after:
            self.win.prompt_restart_for_proxy()
