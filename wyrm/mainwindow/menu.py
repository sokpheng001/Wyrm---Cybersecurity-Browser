#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/menu.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""The ⋮ main menu and the dialogs it opens (help, settings, about)."""
from __future__ import annotations

import sys

from PySide6.QtCore import QProcess
from PySide6.QtGui import QActionGroup, QKeySequence
from PySide6.QtWidgets import QMenu, QMessageBox

from .. import version_label, years
from ..dialogs import SettingsDialog


class MenuMixin:
    """The ⋮ main menu and the dialogs it opens (help, settings, about). (Mixed into MainWindow.)"""

    def _build_menu(self) -> QMenu:
        m = QMenu(self)
        m.addAction("New tab", self._new_tab_focus, QKeySequence("Ctrl+T"))
        a = m.addAction("New Tor window", self.open_tor_window, QKeySequence("Ctrl+Alt+N"))
        a.setEnabled(not self.tor)
        # shortcut lives on the window (works with the menu closed); label shows it the OS's way (⇧⌘N / Ctrl+Shift+N)
        keys = QKeySequence("Ctrl+Shift+N").toString(QKeySequence.SequenceFormat.NativeText)
        m.addAction(f"New private window   {keys}", self.open_private_window)
        if self.tor:
            m.addAction("New Tor identity (new circuit)", self.tor_new_identity)
            m.addAction("Disconnect Tor && close window", self.disconnect_tor)
        m.addSeparator()
        mm = m.addMenu("Mode")
        mgroup = QActionGroup(self)
        self._mode_actions = {}
        for key, label in (("blue", "Blue team — defensive (standard)"), ("red", "Red team — offensive (elite)")):
            act = mm.addAction(label, lambda k=key: self.apply_mode(k))
            act.setCheckable(True)
            act.setData(key)
            act.setChecked(key == self.mode)
            mgroup.addAction(act)
            self._mode_actions[key] = act
        tm = m.addMenu("Theme")
        group = QActionGroup(self)
        self._theme_actions = {}
        for mode, label in (("system", "Follow system"), ("dark", "Dark"), ("light", "Light"),
                            ("hacker", "Hacker (pro dark)")):
            act = tm.addAction(label, lambda md=mode: self.apply_theme(md))
            act.setCheckable(True)
            act.setData(mode)
            act.setChecked(mode == self.theme_mode)
            group.addAction(act)
            self._theme_actions[mode] = act
        m.addSeparator()
        m.addAction("Settings…", self._open_settings, QKeySequence("Ctrl+,"))
        m.addAction("Shields && privacy panel", lambda: self.security.show_tab("Shields"))
        hk = QKeySequence(self.HISTORY_KEYS[0]).toString(QKeySequence.SequenceFormat.NativeText)
        m.addAction(f"History   {hk}", self.open_history)
        m.addAction("Clear browsing data…", self.clear_browsing_data)
        a = m.addAction("Intercept requests…   Ctrl+Alt+I", self.open_intercept)
        a.setEnabled(not self.tor)
        em = m.addMenu("Extensions")
        em.aboutToShow.connect(lambda menu=em: self._ext_fill_menu(menu))
        m.addSeparator()
        m.addAction("Help — how to use Wyrm (F1)", self.open_help)
        m.addAction("Check for updates…", self._check_updates)
        m.addAction("About Wyrm Browser", self._about)
        return m

    def open_help(self):
        """Built-in user guide in a new tab."""
        self.open_url("wyrm://help", new_tab=True)

    def _clear_history_confirm(self):
        if QMessageBox.question(self, "Clear history", "Clear the saved search & address-bar history?") \
                == QMessageBox.StandardButton.Yes:
            self.clear_history()

    def _about(self):
        tor = f"<br>Tor {self.tor.version()} · SOCKS port {self.tor.socks_port}" if self.tor else ""
        box = QMessageBox(self)
        box.setWindowTitle("About Wyrm Browser")
        box.setIconPixmap(self.windowIcon().pixmap(64, 64))
        box.setText(f"<b>Wyrm Browser</b> {version_label()}")
        box.setInformativeText(
                    "A <i>wyrm</i> is a wingless dragon — our mark, and the name of this browser.<br><br>"
                    "Built by <b>ByKh R&amp;D Group</b> · <b>bykh.org</b><br><b>HackPi</b> — Ethical Hackers Group<br>"
                    f"Copyright © {years()} ByKh R&amp;D Group · HackPi{tor}<br><br>"
                    "Chromium engine via Qt WebEngine · Ad/tracker blocking via community filter lists · Tor: Tor Project")
        visit = box.addButton("Visit bykh.org", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Close)
        box.exec()
        if box.clickedButton() is visit:  # open our website in Wyrm itself
            self.open_url("https://bykh.org", new_tab=True)

    def _open_settings(self):
        SettingsDialog(self).exec()

    def prompt_restart_for_proxy(self):
        if QMessageBox.question(self, "Restart required",
                                "Proxy settings apply after a restart. Restart now?") == QMessageBox.StandardButton.Yes:
            args = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv
            QProcess.startDetached(sys.executable, args)
            self._force_close = True
            self.close()
