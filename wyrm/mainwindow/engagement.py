#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/engagement.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Engagements (authorized scope), isolated profiles, scope badge and findings."""
from __future__ import annotations

from PySide6.QtCore import QBuffer, QIODevice, QUrl, Qt
from PySide6.QtWebEngineCore import QWebEngineProfile, QWebEngineScript, QWebEngineSettings
from PySide6.QtWidgets import QMessageBox

from .. import theme
from ..dialogs import EngagementDialog, FindingDialog
from ..scheme import SCHEME
from ..security import rewrite
from ..browser.scripts import FINGERPRINT_JS, YOUTUBE_JS
from ..ui.common import HOME


class EngagementMixin:
    """Engagements (authorized scope), isolated profiles, scope badge and findings. (Mixed into MainWindow.)"""

    # ================================================================ profiles / engagements
    def _profile_for(self, eng) -> QWebEngineProfile:
        key = "tor" if self.tor else "private" if self.private else (f"eng-{eng.id}" if eng else "personal")
        if key in self.profiles:
            return self.profiles[key]
        if self.ephemeral:
            prof = QWebEngineProfile(self)  # off-the-record: no cookies, cache or history touch the disk
        else:
            prof = QWebEngineProfile(f"Wyrm-{key}", self)
            prof.setPersistentStoragePath(str(self.data_dir / "profiles" / key))
            prof.setCachePath(str(self.data_dir / "cache" / key))
        def inject(name, source, subframes=False):
            sc = QWebEngineScript()
            sc.setName(name)
            sc.setSourceCode(source)
            sc.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
            sc.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            sc.setRunsOnSubFrames(subframes)
            prof.scripts().insert(sc)
        if self.shields.enabled("youtube"):
            inject("wyrm-youtube", YOUTUBE_JS)
        if self.shields.enabled("antifp"):  # anti-fingerprinting (PriVaricator-style), runs in all frames
            inject("wyrm-antifp", FINGERPRINT_JS, subframes=True)
        s = prof.settings()
        for attr in (QWebEngineSettings.WebAttribute.PluginsEnabled, QWebEngineSettings.WebAttribute.PdfViewerEnabled,
                     QWebEngineSettings.WebAttribute.FullScreenSupportEnabled,
                     QWebEngineSettings.WebAttribute.ScrollAnimatorEnabled):
            s.setAttribute(attr, True)
        prof.installUrlSchemeHandler(SCHEME, self.scheme_handler)
        prof.downloadRequested.connect(self._on_download)
        self.profiles[key] = prof
        if not self.ephemeral:
            self._ext_attach(prof)  # browser extensions (normal windows only)
        return prof

    def _rules_key(self) -> str:
        return f"rules/eng-{self.engagement.id}" if self.engagement else "rules/personal"

    def _load_rules(self):
        self.rules = rewrite.RuleSet.load(self.settings.value(self._rules_key(), "", type=str))

    def save_rules(self):
        self.settings.setValue(self._rules_key(), self.rules.dump())

    def set_engagement(self, eng, reopen=True):
        same = (eng.id if eng else 0) == (self.engagement.id if self.engagement else 0)
        self.engagement = eng
        self.settings.setValue("engagement", eng.id if eng else 0)
        self._load_rules()
        if not same and reopen:
            # each engagement has its own cookie jar / storage, so its tabs live in their own profile
            self.profile = self._profile_for(eng)
            self.tabbar.blockSignals(True)
            while self.tabbar.count():
                self._remove_tab(0)
            self.tabbar.blockSignals(False)
            self.security.traffic.model.clear()
            self.new_tab(QUrl(HOME))
            self.toast(f"Switched to {'engagement ' + eng.name if eng else 'personal browsing'} (isolated session)")
        self._refresh_engagement_ui()

    def _refresh_engagement_ui(self):
        box = self.eng_box
        box.blockSignals(True)
        box.clear()
        box.addItem("Personal", 0)
        box.setItemData(0, "No engagement: personal browsing session", Qt.ItemDataRole.ToolTipRole)
        for e in self.store.engagements():
            box.addItem(e.name, e.id)
        box.insertSeparator(box.count())
        box.addItem("New engagement…", -1)
        if self.engagement:
            box.addItem("Edit current engagement…", -2)
            box.addItem("Delete current engagement…", -3)
        box.setCurrentIndex(max(0, box.findData(self.engagement.id if self.engagement else 0)))
        box.blockSignals(False)
        self.security.findings.refresh()
        self._update_scope_badge()
        self._set_window_title(self.current_view().title() if self.current_view() else "")

    def _on_engagement_chosen(self, idx):
        data = self.eng_box.itemData(idx)
        if data == -1:
            d = EngagementDialog(self)
            if d.exec():
                self.set_engagement(self.store.save_engagement(d.e))
            else:
                self._refresh_engagement_ui()
        elif data == -2 and self.engagement:
            d = EngagementDialog(self, self.engagement)
            if d.exec():
                self.store.save_engagement(d.e)
                self.engagement = d.e
            self._refresh_engagement_ui()
        elif data == -3 and self.engagement:
            if QMessageBox.question(self, "Delete engagement",
                                    f"Delete '{self.engagement.name}' and all its findings?") == QMessageBox.StandardButton.Yes:
                self.store.delete_engagement(self.engagement.id)
                self.set_engagement(None)
            else:
                self._refresh_engagement_ui()
        elif data is not None and data >= 0:
            self.set_engagement(self.store.engagement(data) if data else None)

    def _update_scope_badge(self):
        v = self.current_view()
        eng = self.engagement
        url = (self._failed.get(v) or v.url()) if v else QUrl()
        if not eng or url.scheme() not in ("http", "https"):
            self.scope_badge.hide()
            return
        ok = eng.in_scope(url.host())
        p = theme.PALETTES[self.theme_name]
        bg, fg = (p["tag_ok_bg"], p["tag_ok_fg"]) if ok else (p["tag_bad_bg"], p["tag_bad_fg"])
        self.scope_badge.setText("In scope" if ok else "Out of scope")
        self.scope_badge.setToolTip(f"{url.host()} vs scope of '{eng.name}': " + ", ".join(eng.scope))
        self.scope_badge.setStyleSheet(f"background:{bg};color:{fg}")
        self.scope_badge.show()

    # ================================================================ findings
    def add_finding_dialog(self, title="", severity="medium", url=None, description="", evidence=""):
        if not self.engagement:
            QMessageBox.information(self, "Findings", "Select or create an engagement first (toolbar, left of the address bar).")
            return
        v = self.current_view()
        url = url or (v.url().toString() if v else "")
        d = FindingDialog(self, title, severity, url, description, evidence, can_screenshot=bool(v))
        if not d.exec():
            return
        shot = None
        if d.shot.isChecked() and v:
            buf = QBuffer()
            buf.open(QIODevice.OpenModeFlag.WriteOnly)
            v.grab().save(buf, "PNG")
            shot = bytes(buf.data())
        self.store.add_finding(self.engagement.id, screenshot=shot, **d.values())
        self.security.findings.refresh()
        self.toast(f"Finding saved to '{self.engagement.name}'")
