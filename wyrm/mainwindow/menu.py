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
        m.addAction(self._act_newtab)   # the single Ctrl+T action (bound once on the window — see chrome.py)
        m.addAction("New window", self.open_new_window, QKeySequence("Ctrl+N"))
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
        vm = m.addMenu("Layout")
        a = vm.addAction("Bookmarks bar", self._toggle_bookmarks_bar)
        a.setCheckable(True)
        a.setChecked(self.settings.value("ui/bookmarks_bar", True, type=bool))
        a = vm.addAction("Vertical tabs", self._toggle_vertical_tabs)
        a.setCheckable(True)
        a.setChecked(self.settings.value("ui/vtabs", False, type=bool))
        m.addSeparator()
        m.addAction("Settings…", self._open_settings, QKeySequence("Ctrl+,"))
        m.addAction("Shields && privacy panel", lambda: self.security.show_tab("Shields"))
        hk = QKeySequence(self.HISTORY_KEYS[0]).toString(QKeySequence.SequenceFormat.NativeText)
        m.addAction(f"History   {hk}", self.open_history)
        m.addAction("Clear browsing data…", self.clear_browsing_data)
        m.addAction("Clear search history", self._clear_history_confirm)
        a = m.addAction("Intercept requests…   Ctrl+Alt+I", self.open_intercept)
        a.setEnabled(not self.tor)
        em = m.addMenu("Extensions")
        em.aboutToShow.connect(lambda menu=em: self._ext_fill_menu(menu))
        m.addAction("Bookmark this page   Ctrl+D", self._bookmark_current)
        m.addAction("Downloads   Ctrl+J", self.show_downloads)
        # Tools (shortcuts shown in the labels; the keys themselves are bound on the window, so not re-bound here)
        tools = m.addMenu("More tools")
        tools.addAction("Find in page   Ctrl+F", self._show_find)
        # zoom row: −  100%  +  (the −/+/% buttons keep the menu open and the % updates live), like other browsers
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QHBoxLayout, QLabel, QToolButton, QWidget, QWidgetAction
        zrow = QWidget()
        zl = QHBoxLayout(zrow)
        zl.setContentsMargins(14, 2, 10, 2)
        zl.setSpacing(6)
        zl.addWidget(QLabel("Zoom"))
        zl.addStretch(1)
        zout = QToolButton(text="−")           # minus
        zpct = QToolButton(text="100%")             # click to reset to 100%
        zin = QToolButton(text="+")
        zpct.setMinimumWidth(50)
        for b, fn in ((zout, lambda: self._zoom(-0.1)), (zpct, lambda: self._zoom(0)), (zin, lambda: self._zoom(0.1))):
            b.setAutoRaise(True)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(fn)
            zl.addWidget(b)
        self._zoom_pct_lbl = zpct                    # _zoom() updates this live
        za = QWidgetAction(tools)
        za.setDefaultWidget(zrow)
        tools.addAction(za)
        tools.aboutToShow.connect(self._refresh_zoom_pct)
        tools.addAction("Full screen   F11", self._toggle_fullscreen)
        tools.addSeparator()
        tools.addAction("Print…   Ctrl+P", self._print_page)
        tools.addAction("Save page as…", self._save_page)
        tools.addAction("View page source   Ctrl+U",
                        lambda: self.current_view() and self.open_url("view-source:"
                        + self.current_view().url().toString(), new_tab=True))
        tools.addAction("Developer tools   F12", lambda: self.inspect(element=False))
        m.addSeparator()
        m.addAction("Help — how to use Wyrm (F1)", self.open_help)
        # Update item shows a count when an update is available/downloaded, and refreshes each time the menu opens.
        self._menu_update_action = m.addAction("Check for updates…", self._update_menu_clicked)
        m.addAction("About Wyrm Browser", self._about)
        m.aboutToShow.connect(self._refresh_menu_update)
        return m

    def _refresh_menu_update(self):
        act = getattr(self, "_menu_update_action", None)
        if act is None:
            return
        info = getattr(self, "_update_info", None)
        if getattr(self, "_pending_update", None):
            act.setText("⬆  Restart to finish updating   (1)")
        elif info and info.get("newer"):
            act.setText(f"⬆  Update to Wyrm {info.get('version', '')}   (1)")
        else:
            act.setText("Check for updates…")

    def _update_menu_clicked(self):
        if getattr(self, "_pending_update", None):
            self._ask_restart()
        elif getattr(self, "_update_info", None) and self._update_info.get("newer"):
            self._open_update()
        else:
            self._check_updates()

    def open_help(self):
        """Built-in user guide in a new tab."""
        self.open_url("wyrm://help", new_tab=True)

    def _clear_history_confirm(self):
        if QMessageBox.question(self, "Clear history", "Clear the saved search & address-bar history?") \
                == QMessageBox.StandardButton.Yes:
            self.clear_history()

    def _about(self):
        tor = f"<br>Tor {self.tor.version()} · SOCKS port {self.tor.socks_port}" if self.tor else ""
        try:   # surface the engine version so an outdated Chromium is visible at a glance (SEC-1)
            from PySide6.QtWebEngineCore import qWebEngineChromiumVersion, qWebEngineVersion
            engine = f"<br>Chromium {qWebEngineChromiumVersion()} · Qt WebEngine {qWebEngineVersion()}"
        except Exception:  # noqa: BLE001
            engine = ""
        box = QMessageBox(self)
        box.setWindowTitle("About Wyrm Browser")
        box.setIconPixmap(self.windowIcon().pixmap(64, 64))
        box.setText(f"<b>Wyrm Browser</b> {version_label()}")
        box.setInformativeText(
                    "A <i>wyrm</i> is a wingless dragon — our mark, and the name of this browser.<br><br>"
                    "Built by <b>ByKh R&amp;D Group</b> · <b>bykh.org</b><br><b>HackPi</b> — Ethical Hackers Group<br>"
                    f"Copyright © {years()} ByKh R&amp;D Group · HackPi{tor}{engine}<br><br>"
                    "Chromium engine via Qt WebEngine · Ad/tracker blocking via community filter lists · Tor: Tor Project")
        visit = box.addButton("Visit bykh.org", QMessageBox.ButtonRole.ActionRole)
        whatsnew = box.addButton("What's new", QMessageBox.ButtonRole.ActionRole)
        close = box.addButton(QMessageBox.StandardButton.Close)
        box.setDefaultButton(close)   # QA-U4: Enter closes the dialog, not "Visit bykh.org"
        box.setEscapeButton(close)
        box.exec()
        if box.clickedButton() is visit:  # open our website in Wyrm itself
            self.open_url("https://bykh.org", new_tab=True)
        elif box.clickedButton() is whatsnew:
            self._show_whats_new()

    def _refresh_zoom_pct(self):
        v = self.current_view()
        pct = int(round((v.zoomFactor() if v else 1.0) * 100))
        lbl = getattr(self, "_zoom_pct_lbl", None)
        if lbl is not None:
            lbl.setText(f"{pct}%")

    def _show_whats_new(self):
        from html import escape
        from pathlib import Path
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QPixmap
        from PySide6.QtWidgets import (QDialog, QFrame, QHBoxLayout, QLabel, QPushButton, QScrollArea,
                                       QVBoxLayout, QWidget)
        from .. import updater
        changes = updater.current_changes()
        d = QDialog(self, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        d.setObjectName("ConfirmDialog")
        d.setMinimumWidth(560)
        d.resize(600, 560)
        outer = QVBoxLayout(d)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        # header: app logo + title
        head = QWidget(objectName="WnHead")
        head.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        hl = QHBoxLayout(head)
        hl.setContentsMargins(24, 20, 24, 16)
        hl.setSpacing(14)
        icon = self._app_icon_path() if hasattr(self, "_app_icon_path") else ""
        pm = QPixmap(icon) if icon else QPixmap()
        if not pm.isNull():
            lg = QLabel()
            lg.setPixmap(pm.scaled(40, 40, Qt.AspectRatioMode.KeepAspectRatio,
                                   Qt.TransformationMode.SmoothTransformation))
            lg.setFixedSize(40, 40)
            hl.addWidget(lg, 0, Qt.AlignmentFlag.AlignVCenter)
        tcol = QVBoxLayout()
        tcol.setSpacing(1)
        t = QLabel("What's new")
        t.setObjectName("DialogTitle")
        sub = QLabel(f"Wyrm Browser {version_label()}")
        sub.setObjectName("Muted")
        tcol.addWidget(t)
        tcol.addWidget(sub)
        hl.addLayout(tcol, 1)
        outer.addWidget(head)
        # scrollable list of changes
        sa = QScrollArea()
        sa.setWidgetResizable(True)
        sa.setFrameShape(QFrame.Shape.NoFrame)
        body = QWidget()
        bl = QVBoxLayout(body)
        bl.setContentsMargins(24, 10, 24, 14)
        bl.setSpacing(12)
        if changes:
            for c in changes:
                row = QLabel("•  " + escape(c))
                row.setObjectName("DialogBody")
                row.setWordWrap(True)
                row.setTextFormat(Qt.TextFormat.RichText)
                bl.addWidget(row)
        else:
            lab = QLabel("See the Releases page for the full changelog.")
            lab.setObjectName("DialogBody")
            bl.addWidget(lab)
        bl.addStretch(1)
        sa.setWidget(body)
        outer.addWidget(sa, 1)
        # footer OK
        foot = QHBoxLayout()
        foot.setContentsMargins(24, 12, 24, 18)
        foot.addStretch(1)
        ok = QPushButton("OK", objectName="Primary")
        ok.setMinimumWidth(110)
        ok.setDefault(True)
        ok.clicked.connect(d.accept)
        foot.addWidget(ok)
        outer.addLayout(foot)
        d.exec()

    def _open_settings(self):
        SettingsDialog(self).exec()

    def prompt_restart_for_proxy(self):
        if QMessageBox.question(self, "Restart required",
                                "Proxy settings apply after a restart. Restart now?") == QMessageBox.StandardButton.Yes:
            args = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv
            QProcess.startDetached(sys.executable, args)
            self._force_close = True
            self.close()
