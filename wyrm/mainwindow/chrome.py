#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/chrome.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Window chrome: tab strip, toolbar, find bar, frame / title-bar handling and keys."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QEvent, QSize, QTimer, QUrl, Qt
from PySide6.QtGui import QAction, QKeySequence, QPixmap
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWidgets import QComboBox, QCompleter, QHBoxLayout, QLabel, QLineEdit, QPushButton, QSizePolicy, QStackedWidget, QTabBar, QToolBar, QToolButton, QVBoxLayout, QWidget

from .. import engines, theme, winframe
from ..widgets import LoadingBar, OfflineBanner
from ..ui.common import HOME, make_icon


class ChromeMixin:
    """Window chrome: tab strip, toolbar, find bar, frame / title-bar handling and keys. (Mixed into MainWindow.)"""

    # ================================================================ chrome
    def _tool(self, icon: str, tip: str, fn=None, keys=()) -> QToolButton:
        b = QToolButton()
        b.setFixedSize(40, 40)  # square, so the hover background is centred on the icon
        b.setIconSize(b.iconSize().scaled(20, 20, Qt.AspectRatioMode.KeepAspectRatio))
        b.setToolTip(tip)
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        self._icon_buttons.append((b, icon))
        if fn:
            b.clicked.connect(fn)
        for k in keys:
            a = QAction(self)
            a.setShortcut(QKeySequence(k))
            a.triggered.connect(fn)
            self.addAction(a)
        return b

    def _build_ui(self):
        self._icon_buttons = []
        root = QWidget(objectName="Root")
        col = QVBoxLayout(root)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)

        strip = QWidget(objectName="TabStrip")
        strip.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        strip.setFixedHeight(41)
        row = QHBoxLayout(strip)
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)
        self.brand = QLabel(objectName="Brand")
        logo = QPixmap(str(Path(__file__).parent.parent / "assets" / "icon.png"))
        if not logo.isNull():
            self.brand.setPixmap(logo.scaled(22, 22, Qt.AspectRatioMode.KeepAspectRatio,
                                             Qt.TransformationMode.SmoothTransformation))
        tor_tag = QLabel(objectName="PrivateTag" if self.private else "TorTag")
        if self.tor:
            tor_tag.setText("Tor")
        elif self.private:
            tor_tag.setText("Private")
            tor_tag.setToolTip("Private window: history, cookies and site data are deleted when you close it")
        self.brand.setToolTip("Private Tor window: traffic goes through the Tor network, nothing is saved to disk"
                              if self.tor else "Private window: nothing is saved" if self.private else "Wyrm Browser")
        self.brand.setContentsMargins(14, 0, 0, 0)
        if sys.platform == "darwin":
            row.addSpacing(64)  # room for the traffic lights (window has no separate title bar on macOS)
            strip.installEventFilter(self)  # drag / double-click the empty strip like a title bar
        row.addWidget(self.brand, 0, Qt.AlignmentFlag.AlignVCenter)
        self.tor_tag = tor_tag
        if self.tor or self.private:
            row.addWidget(tor_tag, 0, Qt.AlignmentFlag.AlignVCenter)
        # Red/Blue team mode chip (click to switch)
        # (equal space logo → chip → tabs; the chip draws its own glow margin)
        from ..widgets import ModeChip
        self.mode_chip = ModeChip()
        self.mode_chip.setObjectName("ModeChip")
        self.mode_chip.clicked.connect(self._toggle_mode)
        row.addSpacing(8)
        row.addWidget(self.mode_chip, 0, Qt.AlignmentFlag.AlignVCenter)
        row.addSpacing(8)
        self.brand_divider = QWidget(objectName="BrandDivider")
        self.brand_divider.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.brand_divider.setFixedSize(1, 24)
        row.addWidget(self.brand_divider, 0, Qt.AlignmentFlag.AlignVCenter)
        self.strip = strip
        self.tabbar = QTabBar(objectName="MainTabs", tabsClosable=True, movable=True, expanding=False, drawBase=False,
                              elideMode=Qt.TextElideMode.ElideRight, usesScrollButtons=True)
        self.tabbar.setDocumentMode(True)
        self.tabbar.tabCloseRequested.connect(self.close_tab)
        self.tabbar.currentChanged.connect(self._on_tab_changed)
        row.addWidget(self.tabbar, 0, Qt.AlignmentFlag.AlignBottom)
        b_new = self._tool("plus", "New tab (Ctrl+T)", self._new_tab_focus, ["Ctrl+T"])
        self._shell_buttons = {b_new}
        row.addWidget(b_new)
        row.addStretch(1)
        if winframe.IS_WINDOWS:  # caption buttons live in the tab strip, like Chrome/Edge
            self.b_min = self._tool("win_min", "Minimize", self.showMinimized)
            self.b_max = self._tool("win_max", "Maximize", self._toggle_max)
            self.b_close = self._tool("win_close", "Close", self.close)
            for b in (self.b_min, self.b_max, self.b_close):
                b.setObjectName("CaptionButton")
                b.setFixedSize(46, 41)
                self._shell_buttons.add(b)
                row.addWidget(b)
            self.b_close.setObjectName("CloseButton")
        # header + nav live in full-width toolbars so they span above the side panels (Carbon UI shell)
        for i, w in enumerate((strip,)):
            tb = QToolBar(objectName="ShellBar", movable=False, floatable=False)
            tb.setContextMenuPolicy(Qt.ContextMenuPolicy.PreventContextMenu)
            tb.addWidget(w)
            self.addToolBar(Qt.ToolBarArea.TopToolBarArea, tb)
        self.addToolBarBreak()

        nav = QWidget(objectName="NavBar")
        nav.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        n = QHBoxLayout(nav)
        n.setContentsMargins(0, 0, 0, 0)
        n.setSpacing(1)
        self.b_back = self._tool("back", "Back (Alt+Left)", lambda: self.current_view().back(), ["Alt+Left"])
        self.b_fwd = self._tool("forward", "Forward (Alt+Right)", lambda: self.current_view().forward(), ["Alt+Right"])
        self.b_reload = self._tool("reload", "Reload (F5)", self._reload_or_stop, ["F5", "Ctrl+R"])
        b_home = self._tool("home", "Home", lambda: self.current_view().setUrl(QUrl(HOME)), ["Alt+Home"])
        for b in (self.b_back, self.b_fwd, self.b_reload, b_home):
            n.addWidget(b)

        self.eng_box = QComboBox(objectName="Engagement")
        self.eng_box.setToolTip("Engagement: authorized target scope + isolated session + findings")
        self._shrinkable(self.eng_box, 130, 190)
        self.eng_box.view().setMinimumWidth(280)
        self.eng_box.activated.connect(self._on_engagement_chosen)
        n.addWidget(self.eng_box)
        self.eng_box.setVisible(not self.ephemeral)  # engagements keep persistent sessions; Tor/private never do

        self.urlbar = QLineEdit(objectName="UrlBar")
        self.urlbar.setPlaceholderText("Search, or type a URL, CVE-ID or domain")
        self.urlbar.setFixedHeight(38)
        self.urlbar.setTextMargins(28, 0, 0, 0)  # reserve space for the icon inside the pill
        self.urlbar.returnPressed.connect(lambda: self.navigate(self.urlbar.text()))
        # address-bar autocomplete: history + live search suggestions (Tor windows never record anything)
        from PySide6.QtGui import QStandardItemModel
        self._history = [] if self.ephemeral else list(self.settings.value("history/entries", [], type=list) or [])
        self._suggest_model = QStandardItemModel(self)
        self._completer = QCompleter(self._suggest_model, self)
        self._completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self._completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self._completer.setCompletionMode(QCompleter.CompletionMode.UnfilteredPopupCompletion)
        self._completer.setMaxVisibleItems(10)
        popup = self._completer.popup()
        popup.setObjectName("UrlPopup")
        popup.setIconSize(QSize(15, 15))
        popup.setSpacing(1)
        self.urlbar.setCompleter(self._completer)
        self._rebuild_suggest_model(self._history[:10], [])
        # debounce live suggestions as the user types
        self._suggest_timer = QTimer(self)
        self._suggest_timer.setSingleShot(True)
        self._suggest_timer.setInterval(160)
        self._suggest_timer.timeout.connect(self._fetch_suggestions)
        self.urlbar.textEdited.connect(lambda _t: self._suggest_timer.start())
        # lock/search icon placed INSIDE the pill, vertically centered (repositioned on resize)
        self.url_icon = QLabel(self.urlbar, objectName="UrlIcon")
        self.url_icon.setFixedSize(20, 20)
        self.url_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.urlbar.installEventFilter(self)
        n.addWidget(self.urlbar, 1, Qt.AlignmentFlag.AlignVCenter)
        self.scope_badge = QLabel(objectName="ScopeBadge")
        self.scope_badge.setFixedHeight(24)
        self.scope_badge.hide()
        n.addSpacing(8)
        n.addWidget(self.scope_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        n.addSpacing(8)

        self.engine_box = QComboBox(objectName="Engine")
        self.engine_box.setToolTip("Search engine for plain queries")
        self._shrinkable(self.engine_box, 160, 200)
        self.engine_box.view().setMinimumWidth(320)  # popup shows full names next to the logos
        for key, e in engines.ENGINES.items():
            self.engine_box.addItem(e.name, key)
        self.engine_box.setIconSize(QSize(16, 16))
        self._load_engine_icons()
        saved = self.settings.value("search/engine", engines.DEFAULT_ENGINE)  # new key: Security Search is the default
        self.engine_box.setCurrentIndex(max(0, self.engine_box.findData(saved)))
        self.engine_box.currentIndexChanged.connect(self._engine_changed)
        n.addWidget(self.engine_box)

        self._dock_actions = []
        for dock, icon, tip, key in ((self.security, "shield", "Security panel (Ctrl+Shift+S)", "Ctrl+Shift+S"),
                                     (self.panel, "book", "Papers panel (Ctrl+B)", "Ctrl+B")):
            b = QToolButton()
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            a = dock.toggleViewAction()
            a.setShortcut(QKeySequence(key))
            a.setToolTip(tip)
            b.setDefaultAction(a)
            self._dock_actions.append((a, icon))  # icon lives on the action so toggling keeps it
            n.addWidget(b)
        b_flag = self._tool("flag", "Add finding for this page (Ctrl+Shift+F)", lambda: self.add_finding_dialog(),
                            ["Ctrl+Shift+F"])
        n.addWidget(b_flag)
        # Shields: blocked-count badge, opens the Shields report
        self.b_shield = self._tool("shields", "Shields", lambda: self.security.show_tab("Shields"))
        # icon-only (centred like every other button); the blocked count is a small corner badge
        self.shield_badge = QLabel(self.b_shield, objectName="Badge")
        self.shield_badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.shield_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.shield_badge.hide()
        n.addWidget(self.b_shield)
        self._shield_timer = QTimer(self, singleShot=True, interval=250)
        self._shield_timer.timeout.connect(self._update_shield_button)
        # main menu (like other browsers): new tab / Tor window / theme / settings / about
        self.b_menu = self._tool("more", "Menu")
        self.b_menu.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.b_menu.setMenu(self._build_menu())
        self.b_menu.setStyleSheet("QToolButton::menu-indicator{image:none;width:0}")
        # "Update" pill (like Brave): hidden until a newer release is found on our GitHub Releases
        self._update_info = None
        self.b_update = QPushButton("  Update", objectName="UpdateButton")
        self.b_update.setIcon(make_icon("download", "#ffffff", 32))
        self.b_update.setCursor(Qt.CursorShape.PointingHandCursor)
        self.b_update.clicked.connect(self._open_update)
        self.b_update.hide()
        n.addWidget(self.b_update, 0, Qt.AlignmentFlag.AlignVCenter)
        n.addWidget(self.b_menu)
        tb = QToolBar(objectName="NavToolBar", movable=False, floatable=False)
        tb.setContextMenuPolicy(Qt.ContextMenuPolicy.PreventContextMenu)
        tb.addWidget(nav)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, tb)
        strip.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        nav.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self.loading_bar = LoadingBar()
        col.addWidget(self.loading_bar)
        self.offline_banner = OfflineBanner(self._retry_failed)
        col.addWidget(self.offline_banner)
        self.stack = QStackedWidget()
        col.addWidget(self.stack, 1)
        self.setCentralWidget(root)
        # hover status bubble (bottom-left, like other browsers) with the smart link verdict
        self.link_bubble = QLabel(self.stack, objectName="LinkBubble")
        self.link_bubble.setTextFormat(Qt.TextFormat.RichText)
        self.link_bubble.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.link_bubble.hide()

        for keys, fn in (
            (["Ctrl+W"], lambda: self.close_tab(self.tabbar.currentIndex())),
            (["Ctrl+L", "F6", "Alt+D"], lambda: (self.urlbar.setFocus(), self.urlbar.selectAll())),
            (["Ctrl+Tab"], lambda: self.tabbar.setCurrentIndex((self.tabbar.currentIndex() + 1) % self.tabbar.count())),
            (["Ctrl+Shift+Tab"], lambda: self.tabbar.setCurrentIndex((self.tabbar.currentIndex() - 1) % self.tabbar.count())),
            (["F12", "Ctrl+Shift+I"], lambda: self.inspect(element=False)),
            (["Ctrl+U"], lambda: self.current_view() and self.open_url("view-source:" + self.current_view().url().toString(), new_tab=True)),
            (["Ctrl++", "Ctrl+="], lambda: self._zoom(0.1)),
            (["Ctrl+-"], lambda: self._zoom(-0.1)),
            (["Ctrl+0"], lambda: self._zoom(0)),
            (["Ctrl+Shift+T"], self.reopen_closed_tab),
            (["Ctrl+PgDown"], lambda: self._cycle_tab(1)),
            (["Ctrl+PgUp"], lambda: self._cycle_tab(-1)),
            (["Ctrl+1"], lambda: self._goto_tab(0)),
            (["Ctrl+2"], lambda: self._goto_tab(1)),
            (["Ctrl+3"], lambda: self._goto_tab(2)),
            (["Ctrl+4"], lambda: self._goto_tab(3)),
            (["Ctrl+5"], lambda: self._goto_tab(4)),
            (["Ctrl+6"], lambda: self._goto_tab(5)),
            (["Ctrl+7"], lambda: self._goto_tab(6)),
            (["Ctrl+8"], lambda: self._goto_tab(7)),
            (["Ctrl+9"], lambda: self._goto_tab(self.tabbar.count() - 1)),
            (["F11"], self._toggle_fullscreen),
            (["F1"], self.open_help),
            (["Ctrl+Shift+N"], self.open_private_window),
            (self.HISTORY_KEYS, self.open_history),
            (["Escape"], self._stop_current),
            (["Ctrl+F", "F3"], self._show_find),
            (["Ctrl+G"], lambda: self._find_step(True)),
            (["Ctrl+P"], self._print_page),
            (["Ctrl+Shift+Delete"], self.clear_browsing_data),
        ):
            a = QAction(self)
            a.setShortcuts([QKeySequence(k) for k in keys])
            a.triggered.connect(fn)
            self.addAction(a)

    # ================================================================ custom title bar (Windows)
    def _toggle_max(self):
        self.showNormal() if self.isMaximized() else self.showMaximized()

    def _is_caption(self, global_pos) -> bool:
        local = self.strip.mapFromGlobal(global_pos)
        if not self.strip.rect().contains(local):
            return False
        child = self.strip.childAt(local)
        if child is None or child in (self.brand, self.brand_divider):
            return True
        if child is self.tabbar:
            return self.tabbar.tabAt(self.tabbar.mapFrom(self.strip, local)) < 0
        return False

    def nativeEvent(self, event_type, message):
        res = winframe.native_event(self, event_type, message, self._is_caption)
        return res if res is not None else super().nativeEvent(event_type, message)

    def showEvent(self, e):
        super().showEvent(e)
        if winframe.IS_WINDOWS and not getattr(self, "_frame_installed", False):
            self._frame_installed = True
            winframe.install(self, theme.PALETTES[self.theme_name]["shell"])

    def changeEvent(self, e):
        super().changeEvent(e)
        if winframe.IS_WINDOWS and hasattr(self, "b_max") and e.type() == e.Type.WindowStateChange:
            icon = "win_restore" if self.isMaximized() else "win_max"
            self.b_max.setIcon(make_icon(icon, theme.PALETTES[self.theme_name]["shell_text"]))
            self.b_max.setToolTip("Restore" if self.isMaximized() else "Maximize")
            self._icon_buttons = [(b, icon if b is self.b_max else n) for b, n in self._icon_buttons]

    # ---------------------------------------------------------------- find in page (Ctrl+F)
    def _build_find_bar(self):
        bar = QWidget(self.stack, objectName="FindBar")
        bar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        h = QHBoxLayout(bar)
        h.setContentsMargins(8, 4, 6, 4)
        h.setSpacing(4)
        self._find_input = QLineEdit()
        self._find_input.setPlaceholderText("Find in page")
        self._find_input.setFixedWidth(220)
        self._find_input.setFrame(False)
        self._find_input.textChanged.connect(lambda t: self._do_find(t, True))
        self._find_input.returnPressed.connect(lambda: self._find_step(True))
        h.addWidget(self._find_input)
        self._find_count = QLabel("")
        self._find_count.setObjectName("Muted")
        h.addWidget(self._find_count)
        for txt, fn in (("‹", lambda: self._find_step(False)), ("›", lambda: self._find_step(True)),
                        ("✕", self._hide_find)):
            b = QToolButton()
            b.setText(txt)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.clicked.connect(fn)
            h.addWidget(b)
        bar.hide()
        self._findbar = bar

    def _show_find(self):
        if not hasattr(self, "_findbar"):
            self._build_find_bar()
        self._findbar.adjustSize()
        self._findbar.move(self.stack.width() - self._findbar.width() - 16, 8)
        self._findbar.show()
        self._findbar.raise_()
        self._find_input.setFocus()
        self._find_input.selectAll()

    def _hide_find(self):
        if hasattr(self, "_findbar"):
            self._findbar.hide()
        v = self.current_view()
        if v:
            v.findText("")  # clear highlights

    def _do_find(self, text, forward=True):
        v = self.current_view()
        if not v:
            return
        flags = QWebEnginePage.FindFlag.FindBackward if not forward else QWebEnginePage.FindFlag(0)

        def cb(result):
            try:
                n = result.numberOfMatches()
                self._find_count.setText(f"{result.activeMatch()}/{n}" if n else ("No matches" if text else ""))
            except Exception:  # noqa: BLE001
                pass
        v.findText(text, flags, cb)

    def _find_step(self, forward):
        if hasattr(self, "_find_input") and self._find_input.text():
            self._do_find(self._find_input.text(), forward)

    def eventFilter(self, obj, ev):
        if obj is getattr(self, "urlbar", None) and ev.type() == QEvent.Type.Resize:
            self.url_icon.move(11, (self.urlbar.height() - self.url_icon.height()) // 2)
        elif obj is getattr(self, "security", None) and ev.type() == QEvent.Type.Resize:
            if not getattr(self, "_window_resizing", False):
                self._panel_ratio_timer.start()
        elif obj is getattr(self, "strip", None) and sys.platform == "darwin":
            # macOS (no title bar): the empty tab strip behaves like one — drag to move, double-click to zoom
            t = ev.type()
            if t in (QEvent.Type.MouseButtonPress, QEvent.Type.MouseButtonDblClick) \
                    and ev.button() == Qt.MouseButton.LeftButton \
                    and self._is_caption(ev.globalPosition().toPoint()):
                if t == QEvent.Type.MouseButtonDblClick:
                    self.showNormal() if self.isMaximized() else self.showMaximized()
                elif self.windowHandle() is not None:
                    self.windowHandle().startSystemMove()
                return True
        return super().eventFilter(obj, ev)

    def keyPressEvent(self, e):
        if e.key() == Qt.Key.Key_Escape and self.current_view():
            self.current_view().stop()
            self._sync_chrome()
        super().keyPressEvent(e)
