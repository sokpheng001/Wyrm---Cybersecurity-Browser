#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/shields.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Security panel → Shields: what was blocked and all protection settings."""
from __future__ import annotations

from html import escape

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor, QGuiApplication
from PySide6.QtWidgets import QCheckBox, QComboBox, QHBoxLayout, QHeaderView, QLabel, QPushButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget


# =================================================================== Shields
class ShieldsTab(QWidget):
    CATS = [("ads", "Ads"), ("trackers", "Trackers"), ("malware", "Malware"), ("phishing", "Phishing"),
            ("youtube", "YouTube ads"), ("popups", "Pop-ups"), ("params", "Tracking params removed"),
            ("upgraded", "Upgraded to HTTPS")]
    # (key, short label, details shown as tooltip) — short labels keep the panel usable when narrow
    TOGGLES = [("ads", "Block ads", ""),
               ("antifp", "Resist fingerprinting", "Canvas / WebGL / audio noise. Applies to new tabs."),
               ("trackers", "Block trackers", "Filter lists + HackPi beacon heuristics"),
               ("malware", "Block malware && phishing", "Blocks known malware and phishing sites"),
               ("linkguard", "Smart link check", "Phishing heuristics on links you open"),
               ("popups", "Block ad pop-ups", ""),
               ("params", "Strip tracking parameters", "Removes utm_*, fbclid, gclid… from links"),
               ("youtube", "Remove YouTube ads", "Applies to new tabs")]

    def __init__(self, win):
        super().__init__()
        self.win = win
        v = QVBoxLayout(self)
        head = QHBoxLayout()
        self.site = QLabel("")
        self.site.setWordWrap(True)
        head.addWidget(self.site, 1)
        self.site_toggle = QCheckBox("Shields up for this site")
        self.site_toggle.toggled.connect(self._site_toggled)
        head.addWidget(self.site_toggle)
        v.addLayout(head)
        self.grid = QLabel("")
        self.grid.setTextFormat(Qt.TextFormat.RichText)
        self.grid.setWordWrap(True)
        self._stat_cols = 4
        v.addWidget(self.grid)
        self.list = QTreeWidget()
        self.list.setHeaderLabels(["Blocked", "Request"])
        self.list.setRootIsDecorated(False)
        self.list.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.list.itemDoubleClicked.connect(lambda it, _c: QGuiApplication.clipboard().setText(it.text(1)))
        self.list.setToolTip("Double-click to copy the URL")
        v.addWidget(self.list, 1)

        opts = QLabel("<b>Protection</b>")
        v.addWidget(opts)
        hint = QLabel("Tip: to inspect a site's ads for malvertising, turn off <b>Shields up for this site</b> "
                      "above (loads ads on that site only), or untick <b>Block ads</b> globally.")
        hint.setObjectName("Muted")
        hint.setWordWrap(True)
        v.addWidget(hint)
        self.checks = {}
        for key, label, tip in self.TOGGLES:
            c = QCheckBox(label)
            if tip:
                c.setToolTip(tip)
            c.setChecked(win.shields.enabled(key))
            c.toggled.connect(lambda on, k=key: (win.shields.set_enabled(k, on), self._reload_hint()))
            v.addWidget(c)
            self.checks[key] = c

        v.addWidget(QLabel("<b>Encryption</b>"))
        self.https = QCheckBox("HTTPS-Only mode")
        self.https.setToolTip("Upgrade every connection to HTTPS")
        self.https.setChecked(win.https_only())
        self.https.toggled.connect(lambda on: win.settings.setValue("privacy/https_only", on))
        v.addWidget(self.https)
        v.addWidget(QLabel("Encrypted DNS (DNS-over-HTTPS)"))
        row = QHBoxLayout()
        self.doh_mode = QComboBox()
        for key, label in (("secure", "On (fallback to system DNS)"), ("strict", "Strict (encrypted only)"), ("off", "Off")):
            self.doh_mode.addItem(label, key)
        self.doh_mode.setCurrentIndex(max(0, self.doh_mode.findData(win.settings.value("privacy/doh_mode", "secure"))))
        self.doh_prov = QComboBox()
        for key, (label, _url) in win.DOH.items():
            self.doh_prov.addItem(label, key)
        self.doh_prov.setCurrentIndex(max(0, self.doh_prov.findData(win.settings.value("privacy/doh_provider", "cloudflare"))))
        for box, key in ((self.doh_mode, "privacy/doh_mode"), (self.doh_prov, "privacy/doh_provider")):
            box.currentIndexChanged.connect(lambda _i, b=box, k=key: (win.settings.setValue(k, b.currentData()), win.apply_dns()))
        for box in (self.doh_mode, self.doh_prov):  # may shrink below their longest item
            box.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon)
            box.setMinimumContentsLength(8)
            box.view().setMinimumWidth(240)
        row.addWidget(self.doh_mode, 1)
        row.addWidget(self.doh_prov, 1)
        v.addLayout(row)
        if win.tor:
            self.doh_mode.setEnabled(False)
            self.doh_prov.setEnabled(False)
            self.doh_mode.setToolTip("Tor windows resolve DNS inside the Tor network")

        foot = QHBoxLayout()
        self.lists = QLabel("")
        self.lists.setObjectName("Muted")
        self.lists.setWordWrap(True)
        foot.addWidget(self.lists, 1)
        upd = QPushButton("Update lists")
        upd.clicked.connect(self._update_lists)
        upd.setMinimumWidth(130)
        foot.addWidget(upd, 0, Qt.AlignmentFlag.AlignRight)
        v.addLayout(foot)
        if win.tor:
            trow = QHBoxLayout()
            self.tor_label = QLabel("")
            self.tor_label.setWordWrap(True)
            trow.addWidget(self.tor_label, 1)
            nb = QPushButton("New identity")
            nb.clicked.connect(win.tor_new_identity)
            db = QPushButton("Disconnect Tor")
            db.setObjectName("Danger")
            db.clicked.connect(win.disconnect_tor)
            for b in (nb, db):  # same width + same (right) side, aligned with Update lists above
                b.setMinimumWidth(130)
                trow.addWidget(b, 0, Qt.AlignmentFlag.AlignRight)
            v.addLayout(trow)
        self.refresh()

    def resizeEvent(self, ev):  # re-flow the counters when the panel is resized
        super().resizeEvent(ev)
        if max(2, min(4, (self.width() - 32) // 120)) != self._stat_cols:
            self.refresh()

    def _reload_hint(self):
        self.win.toast("Shield settings changed: reload the page to apply")

    def sync_from_settings(self):
        """Reflect settings changed elsewhere (the Settings dialog) in these controls."""
        for key, cb in self.checks.items():
            cb.blockSignals(True)
            cb.setChecked(self.win.shields.enabled(key))
            cb.blockSignals(False)
        self.https.blockSignals(True)
        self.https.setChecked(self.win.https_only())
        self.https.blockSignals(False)

    def _site_toggled(self, on):
        host = self._host()
        if host:
            self.win.shields.set_site_enabled(host, on)
            v = self.win.current_view()
            if v:
                v.reload()

    def _host(self) -> str:
        v = self.win.current_view() if hasattr(self.win, "tabbar") else None
        return v.url().host() if v and v.url().scheme().startswith("http") else ""

    def _update_lists(self):
        self.lists.setText("Downloading filter lists…")
        from .. import shields as sm
        self.win.runner.run(lambda: sm.build_engines(sm.fetch_lists(self.win.shields.cache)), self.win._filters_ready)

    def refresh(self):
        v = self.win.current_view() if hasattr(self.win, "tabbar") else None
        st = v.stats if v else None
        host = self._host()
        self.site.setText(f"<b>{escape(host)}</b>" if host else "<span style='color:gray'>No website open</span>")
        self.site_toggle.blockSignals(True)
        self.site_toggle.setEnabled(bool(host))
        self.site_toggle.setChecked(self.win.shields.site_enabled(host) if host else True)
        self.site_toggle.blockSignals(False)
        cells = []
        for key, label in self.CATS:
            n = st.counts.get(key, 0) if st else 0
            color = "#da1e28" if key in ("malware", "phishing") and n else ("#4589ff" if n else "#8d8d8d")
            cells.append(f"<td style='padding:6px 14px 6px 0'><span style='font-size:20px;font-weight:300;color:{color}'>{n}"
                         f"</span><br><span style='color:gray;font-size:11px'>{label}</span></td>")
        per = max(2, min(4, (self.width() - 32) // 120))  # columns that fit the panel width
        self._stat_cols = per
        rows = "".join("<tr>" + "".join(cells[i:i + per]) + "</tr>" for i in range(0, len(cells), per))
        total = self.win.shields.total_blocked
        self.grid.setText(f"<table>{rows}</table><span style='color:gray'>{total:,} blocked since install</span>")
        self.list.clear()
        for cat, url, rtype in reversed((st.blocked if st else [])[-500:]):
            it = QTreeWidgetItem([cat, url])
            it.setToolTip(1, f"{rtype}: {url}")
            if cat in ("malware", "phishing", "suspicious"):
                it.setForeground(0, QBrush(QColor("#da1e28")))
            self.list.addTopLevelItem(it)
        rules = self.win.shields.rule_counts()
        r = " · ".join(f"{k} {n:,}" for k, n in rules.items()) or "not downloaded yet"
        self.lists.setText(f"Filter rules: {r} · updated {self.win.shields.last_updated()}.")
        if self.win.tor and hasattr(self, "tor_label"):
            self.tor_label.setText(f"<b>Tor circuit:</b> {escape(self.win.tor.circuit_summary())}")

    def showEvent(self, e):
        super().showEvent(e)
        self.refresh()
