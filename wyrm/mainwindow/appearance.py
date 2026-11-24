#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/appearance.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Light/dark theme and Red/Blue team mode."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWidgets import QApplication

from .. import pages, theme, winframe
from ..ui.common import make_icon


class AppearanceMixin:
    """Light/dark theme and Red/Blue team mode. (Mixed into MainWindow.)"""

    # ================================================================ theme / settings
    def _effective_theme(self) -> str:
        if self.theme_mode in ("dark", "light", "hacker"):
            return self.theme_mode
        scheme = QGuiApplication.styleHints().colorScheme()
        return "light" if scheme == Qt.ColorScheme.Light else "dark"

    def apply_theme(self, mode: str):
        """mode: 'dark' | 'light' | 'hacker' | 'system' (follows the OS setting live)."""
        self.theme_mode = mode
        self.settings.setValue("theme", mode)
        name = self._effective_theme()
        self.theme_name = name
        for act in getattr(self, "_theme_actions", {}).values():
            act.setChecked(act.data() == mode)
        app = QApplication.instance()
        app.setStyle(theme.AppStyle())
        app.setPalette(theme.palette(name, self.mode))
        app.setStyleSheet(theme.stylesheet(name, self.data_dir / "ui", self.mode))
        p = theme.resolve_palette(name, self.mode)
        pages.THEME = "dark" if name == "hacker" else name  # internal pages: dark styling
        pages.MODE = self.mode
        self.loading_bar.COLOR = QColor(p["interactive"])
        ic = p["icon"]
        for btn, icon in self._icon_buttons:
            btn.setIcon(make_icon(icon, p["shell_text"] if btn in self._shell_buttons else ic))
        for act, icon in self._dock_actions:
            act.setIcon(make_icon(icon, ic))
        winframe.set_border_color(self, p["shell"]) if getattr(self, "_frame_installed", False) else None
        self._update_mode_chip()
        if hasattr(self, "_refresh_bookmarks_bar"):
            self._refresh_bookmarks_bar()   # recolour generic/fallback bookmark icons for the new theme
        self._sync_chrome()
        for i in range(self.tabbar.count()):  # internal pages follow the theme/mode
            view = self.tabbar.tabData(i)
            if view.url().scheme() == "wyrm":
                # bypass cache: wyrm:// pages are dynamic (theme/mode), a soft reload serves a stale copy
                view.page().triggerAction(QWebEnginePage.WebAction.ReloadAndBypassCache)

    def apply_mode(self, mode: str):
        """Red (offensive/elite) ↔ Blue (defensive/standard): swaps the accent and start-page emphasis."""
        self.mode = mode if mode in ("blue", "red") else "blue"
        self.settings.setValue("mode", self.mode)
        for act in getattr(self, "_mode_actions", {}).values():
            act.setChecked(act.data() == self.mode)
        # default the security panel to the mode's primary workflow
        self.security.show_tab("Recon" if self.mode == "red" else "Shields")
        self.apply_theme(self.theme_mode)  # re-applies palette/stylesheet with the mode accent + reloads pages
        if self.mode == "red":
            self.toast("Red team mode is ON — offensive workflow: recon and testing tools first. "
                       "Click the RED TEAM chip to switch back.", 4500)
        else:
            self.toast("Blue team mode is ON — defensive workflow: protection and analysis first. "
                       "Click the BLUE TEAM chip to switch.", 4500)

    def _update_mode_chip(self):
        if not hasattr(self, "mode_chip"):
            return
        red = self.mode == "red"
        self.mode_chip.set_mode("RED TEAM" if red else "BLUE TEAM", "#da1e28" if red else "#0f62fe")
        self.mode_chip.setToolTip("Red team (offensive/elite) — click to switch" if red
                                  else "Blue team (defensive/standard) — click to switch")

    def _toggle_mode(self):
        self.apply_mode("blue" if self.mode == "red" else "red")
