#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/chrome.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Window chrome: tab strip, toolbar, find bar, frame / title-bar handling and keys."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QEvent, QSize, QTimer, QUrl, Qt
from PySide6.QtGui import QAction, QKeySequence, QPixmap
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWidgets import QComboBox, QCompleter, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem, QMenu, QPushButton, QSizePolicy, QStackedWidget, QTabBar, QToolBar, QToolButton, QVBoxLayout, QWidget

from .. import engines, theme, winframe
from ..widgets import InfoBanner, LoadingBar, OfflineBanner
from ..ui.common import HOME, make_icon


class ChromeMixin:
    """Window chrome: tab strip, toolbar, find bar, frame / title-bar handling and keys. (Mixed into MainWindow.)"""

    # ================================================================ chrome

    def _load_typed_history(self) -> list:
        """Typed address-bar entries from history.db. B6: a list still in QSettings (history/entries — rewritten
        in full on every navigation) is merged in once and the key deleted, so history has a single store."""
        db = getattr(self, "history_db", None)
        legacy = self.settings.value("history/entries", None, type=list)
        if db is None:
            return list(legacy or [])
        if legacy is not None:
            try:
                db.import_typed(legacy)
                self.settings.remove("history/entries")
            except Exception:  # noqa: BLE001 — keep the old list rather than lose it
                return list(legacy or [])
        return db.typed(500)
    def _tool(self, icon: str, tip: str, fn=None, keys=()) -> QToolButton:
        b = QToolButton()
        b.setFixedSize(40, 40)  # square, so the hover background is centred on the icon
        b.setIconSize(b.iconSize().scaled(20, 20, Qt.AspectRatioMode.KeepAspectRatio))
        b.setToolTip(tip)
        import re as _re
        b.setAccessibleName(_re.split(r"\s*\(|\s{2,}", tip)[0].strip())  # screen-reader name (tooltip minus shortcut)
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
        self.tabbar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tabbar.customContextMenuRequested.connect(self._tab_context_menu)
        row.addWidget(self.tabbar, 0, Qt.AlignmentFlag.AlignBottom)
        self._strip_row = row                      # kept so vertical-tabs mode can move the tab bar out and back
        self._tab_idx = row.indexOf(self.tabbar)
        self._vertical_tabs = False
        b_new = self._tool("plus", "New tab (Ctrl+T)", self._new_tab_focus)
        # single Ctrl+T action shared by the toolbar button and the menu (two bindings = ambiguous = fires neither)
        self._act_newtab = QAction("New tab", self)
        self._act_newtab.setShortcut(QKeySequence("Ctrl+T"))
        self._act_newtab.triggered.connect(lambda: self._new_tab_focus())
        self.addAction(self._act_newtab)
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

        self.nav = nav = QWidget(objectName="NavBar")
        nav.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        nav.installEventFilter(self)   # QA-U1: re-flow the toolbar when it gets too narrow
        n = QHBoxLayout(nav)
        n.setContentsMargins(0, 0, 0, 0)
        n.setSpacing(1)
        self.b_back = self._tool("back", "Back (Alt+Left)", lambda: self.current_view().back(), ["Alt+Left"])
        self.b_fwd = self._tool("forward", "Forward (Alt+Right)", lambda: self.current_view().forward(), ["Alt+Right"])
        self.b_reload = self._tool("reload", "Reload (F5)\nHard reload, bypass cache (Ctrl+Shift+R)",
                                   self._reload_or_stop, ["F5", "Ctrl+R"])
        b_home = self._tool("home", "Home", lambda: self.current_view().setUrl(QUrl(HOME)), ["Alt+Home"])
        for b in (self.b_back, self.b_fwd, self.b_reload, b_home):
            n.addWidget(b)

        self.eng_box = QComboBox(objectName="Engagement")
        self.eng_box.setAccessibleName("Engagement")
        self.eng_box.setToolTip("Engagement: authorized target scope + isolated session + findings")
        self._shrinkable(self.eng_box, 130, 190)
        self.eng_box.view().setMinimumWidth(280)
        self.eng_box.activated.connect(self._on_engagement_chosen)
        n.addWidget(self.eng_box)
        self.eng_box.setVisible(not self.ephemeral)  # engagements keep persistent sessions; Tor/private never do

        self.urlbar = QLineEdit(objectName="UrlBar")
        self.urlbar.setAccessibleName("Address and search")
        self.urlbar.setPlaceholderText("Search, or type a URL, CVE-ID or domain")
        self.urlbar.setFixedHeight(38)
        self.urlbar.setMinimumWidth(240)   # QA-U1: keep the address bar usable; other widgets collapse instead
        self.urlbar.setTextMargins(28, 0, 0, 0)  # reserve space for the icon inside the pill
        self.urlbar.returnPressed.connect(lambda: self.navigate(self.urlbar.text()))
        self.urlbar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.urlbar.customContextMenuRequested.connect(self._urlbar_context_menu)
        # address-bar autocomplete: history + live search suggestions (Tor windows never record anything)
        from PySide6.QtGui import QStandardItemModel
        self._history = [] if self.ephemeral else self._load_typed_history()
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
        self.url_icon.setCursor(Qt.CursorShape.PointingHandCursor)
        self.url_icon.installEventFilter(self)   # click the lock to view the HTTPS certificate
        # bookmark star inside the pill (right side): filled when the page is bookmarked, click to toggle (L-9)
        self.bm_star = QLabel(self.urlbar, objectName="BmStar")
        self.bm_star.setFixedSize(22, 22)
        self.bm_star.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.bm_star.setCursor(Qt.CursorShape.PointingHandCursor)
        self.bm_star.installEventFilter(self)
        self.urlbar.setTextMargins(28, 0, 28, 0)   # reserve room for the lock (left) and the star (right)
        self.urlbar.installEventFilter(self)
        n.addWidget(self.urlbar, 1, Qt.AlignmentFlag.AlignVCenter)
        self.scope_badge = QLabel(objectName="ScopeBadge")
        self.scope_badge.setFixedHeight(24)
        self.scope_badge.hide()
        n.addSpacing(8)
        n.addWidget(self.scope_badge, 0, Qt.AlignmentFlag.AlignVCenter)
        n.addSpacing(8)

        self.engine_box = QComboBox(objectName="Engine")
        self.engine_box.setAccessibleName("Search engine")
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
        # Security panel: keyboard shortcut only (no toolbar button) — the Shields button on the right already
        # opens this panel, so a second shield icon here was redundant.
        sec_toggle = self.security.toggleViewAction()
        sec_toggle.setShortcut(QKeySequence("Ctrl+Shift+S"))
        sec_toggle.setToolTip("Security panel (Ctrl+Shift+S)")
        self.addAction(sec_toggle)
        # Papers panel: toolbar toggle button
        b = QToolButton()
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        a = self.panel.toggleViewAction()
        a.setShortcut(QKeySequence("Ctrl+B"))
        a.setToolTip("Papers panel (Ctrl+B)")
        b.setDefaultAction(a)
        self._dock_actions.append((a, "book"))  # icon lives on the action so toggling keeps it
        n.addWidget(b)
        self._nav_papers_btn = b
        b_flag = self._tool("flag", "Add finding for this page (Ctrl+Shift+F)", lambda: self.add_finding_dialog(),
                            ["Ctrl+Shift+F"])
        n.addWidget(b_flag)
        self._nav_flag_btn = b_flag
        # Shields: blocked-count badge; true toggle — opens the Shields view, or closes the panel if it's
        # already showing Shields (so one button both opens and closes the same view — UX-1).
        self.b_shield = self._tool("shields", "Shields & security panel (Ctrl+Shift+S)",
                                   lambda: self._toggle_shields_panel())
        # icon-only (centred like every other button); the blocked count is a small corner badge
        self.shield_badge = QLabel(self.b_shield, objectName="Badge")
        self.shield_badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.shield_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.shield_badge.hide()
        n.addWidget(self.b_shield)
        # Intercept (Burp-style): opens the Intercept window; highlighted while requests are being held
        # Downloads (like other browsers): opens the downloads list; a badge shows active/finished counts
        self.b_downloads = self._tool("download", "Downloads (Ctrl+J)", lambda: self.show_downloads(), ["Ctrl+J"])
        self.dl_badge = QLabel(self.b_downloads, objectName="Badge")
        self.dl_badge.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.dl_badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.dl_badge.hide()
        n.addWidget(self.b_downloads)
        self.b_int = self._tool("intercept", "Intercept requests: hold, edit, forward or drop (Ctrl+Alt+I)",
                                lambda: self.open_intercept())
        self.b_int.setObjectName("InterceptButton")
        self.b_int.setVisible(not self.tor)
        n.addWidget(self.b_int)
        # Extensions (puzzle piece, like Chrome): click lists your extensions; each opens its popup
        self.b_ext = self._tool("puzzle", "Extensions")
        self.b_ext.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        ext_menu = QMenu(self.b_ext)
        ext_menu.aboutToShow.connect(lambda m=ext_menu: self._ext_fill_menu(m))
        self.b_ext.setMenu(ext_menu)
        self.b_ext.setStyleSheet("QToolButton::menu-indicator{image:none;width:0}")
        self.b_ext.setVisible(not self.ephemeral)  # private / Tor windows never run extensions
        n.addWidget(self.b_ext)
        self._shield_timer = QTimer(self, singleShot=True, interval=250)
        self._shield_timer.timeout.connect(self._update_shield_button)
        # main menu (like other browsers): new tab / Tor window / theme / settings / about
        self.b_menu = self._tool("more", "Menu")
        self.b_menu.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.b_menu.setMenu(self._build_menu())
        self.b_menu.setStyleSheet("QToolButton::menu-indicator{image:none;width:0}")
        # always-available "check for updates" button (neutral toolbar icon) so the user can trigger a check anytime
        self.b_checkupd = self._tool("sync", "Check for updates", lambda: self._check_updates(True))
        n.addWidget(self.b_checkupd)
        # "Update" pill (like Brave): hidden until a newer release is found on our GitHub Releases
        self._update_info = None
        self.b_update = QPushButton("  Update", objectName="UpdateButton")
        self.b_update.setIcon(make_icon("download", "#ffffff", 32))
        self.b_update.setCursor(Qt.CursorShape.PointingHandCursor)
        self.b_update.clicked.connect(self._open_update)
        self.b_update.hide()
        n.addWidget(self.b_update, 0, Qt.AlignmentFlag.AlignVCenter)
        # QA-U1: an overflow menu for lower-priority tools, shown only when the toolbar is too narrow
        self.b_overflow = QToolButton()
        self.b_overflow.setText("»")
        self.b_overflow.setToolTip("More tools")
        self.b_overflow.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._overflow_menu = QMenu(self.b_overflow)
        self.b_overflow.setMenu(self._overflow_menu)
        self.b_overflow.setStyleSheet("QToolButton::menu-indicator{image:none;width:0}")
        self.b_overflow.hide()
        n.addWidget(self.b_overflow)
        # (widget, menu label, callback) — collapsed into the overflow menu below the width breakpoint
        self._collapsible = [
            (self.engine_box, "Search engine…", lambda: self.engine_box.showPopup()),
            (self._nav_papers_btn, "Papers panel (Ctrl+B)", lambda: self.panel.toggleViewAction().trigger()),
            (self._nav_flag_btn, "Add finding for this page (Ctrl+Shift+F)", lambda: self.add_finding_dialog()),
            (self.b_checkupd, "Check for updates", lambda: self._check_updates(True)),
        ]
        n.addWidget(self.b_menu)
        QTimer.singleShot(0, self._init_responsive_nav)
        tb = QToolBar(objectName="NavToolBar", movable=False, floatable=False)
        tb.setContextMenuPolicy(Qt.ContextMenuPolicy.PreventContextMenu)
        tb.addWidget(nav)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, tb)
        strip.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        nav.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        # bookmarks bar (top, like other browsers): the user's shortcuts + folders, folders open a drop-down
        self.addToolBarBreak()
        self.bookmarks_bar = QWidget(objectName="BookmarksBar")
        self.bookmarks_bar.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self._bm_layout = QHBoxLayout(self.bookmarks_bar)
        self._bm_layout.setContentsMargins(6, 2, 6, 2)
        self._bm_layout.setSpacing(1)
        self.bookmarks_bar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.bookmarks_bar.customContextMenuRequested.connect(self._bookmarks_bar_menu)
        self._bm_toolbar = QToolBar(objectName="BookmarksToolBar", movable=False, floatable=False)
        self._bm_toolbar.setContextMenuPolicy(Qt.ContextMenuPolicy.PreventContextMenu)
        self._bm_toolbar.addWidget(self.bookmarks_bar)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self._bm_toolbar)
        self._bm_toolbar.setVisible(self.settings.value("ui/bookmarks_bar", True, type=bool))
        QTimer.singleShot(0, self._refresh_bookmarks_bar)

        self.loading_bar = LoadingBar()
        col.addWidget(self.loading_bar)
        self.offline_banner = OfflineBanner(self._retry_failed)
        col.addWidget(self.offline_banner)
        self.store_banner = InfoBanner()  # "Add to Wyrm Browser" on Chrome Web Store extension pages
        col.addWidget(self.store_banner)
        self.insecure_banner = InfoBanner()   # persistent red warning while TLS errors are being ignored (H-2)
        self.insecure_banner.setObjectName("InsecureBanner")
        col.addWidget(self.insecure_banner)
        # vertical-tabs panel (like Edge/Arc): a readable list of tabs on the left when the user turns it on
        self.vtabs_panel = QWidget(objectName="VTabs")
        self.vtabs_panel.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.vtabs_panel.setFixedWidth(220)
        vcol = QVBoxLayout(self.vtabs_panel)
        vcol.setContentsMargins(6, 6, 6, 6)
        vcol.setSpacing(6)
        self.vtab_list = QListWidget(objectName="VTabList")
        self.vtab_list.setIconSize(QSize(16, 16))
        self.vtab_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.vtab_list.customContextMenuRequested.connect(self._vtab_menu)
        self.vtab_list.currentRowChanged.connect(self._vtab_row_changed)
        vcol.addWidget(self.vtab_list, 1)
        vnew = QPushButton("  +   New tab", objectName="VTabNew")
        vnew.setCursor(Qt.CursorShape.PointingHandCursor)
        vnew.clicked.connect(self._new_tab_focus)
        vcol.addWidget(vnew)
        self.vtabs_panel.hide()

        self.stack = QStackedWidget()
        content = QWidget(objectName="Content")
        crow = QHBoxLayout(content)
        crow.setContentsMargins(0, 0, 0, 0)
        crow.setSpacing(0)
        crow.addWidget(self.vtabs_panel)
        crow.addWidget(self.stack, 1)
        col.addWidget(content, 1)
        self.setCentralWidget(root)
        if self.settings.value("ui/vtabs", False, type=bool):
            self._apply_tab_orientation(True)
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
            (["Ctrl+Shift+R", "Ctrl+F5"], self._hard_reload),
            (["F11"], self._toggle_fullscreen),
            (["F1"], self.open_help),
            (["Ctrl+Shift+N"], self.open_private_window),
            (["Ctrl+Shift+B"], self._toggle_bookmarks_bar),
            (["Ctrl+D"], self._bookmark_current),
            (self.HISTORY_KEYS, self.open_history),
            (["Escape"], self._stop_current),
            (["Ctrl+F", "F3"], self._show_find),
            (["Ctrl+G"], lambda: self._find_step(True)),
            (["Ctrl+P"], self._print_page),
            (["Ctrl+Shift+Delete"], self.clear_browsing_data),
            (["Ctrl+Alt+I"], self.open_intercept),
        ):
            a = QAction(self)
            a.setShortcuts([QKeySequence(k) for k in keys])
            a.triggered.connect(fn)
            self.addAction(a)
        self._check_duplicate_shortcuts()

    def _check_duplicate_shortcuts(self):
        """Debug aid: warn if any key sequence is bound on two window actions (Qt then fires neither — see H-3)."""
        from PySide6.QtGui import QAction as _QAction
        seen: dict = {}
        for act in self.findChildren(_QAction):
            for ks in act.shortcuts():
                s = ks.toString()
                if s:
                    seen.setdefault(s, []).append(act.text() or act.objectName() or "?")
        dupes = {s: names for s, names in seen.items() if len(names) > 1}
        if dupes:
            import sys
            print(f"[Wyrm] duplicate window shortcuts (fix these): {dupes}", file=sys.stderr)

    # ---------------------------------------------------------------- address-bar menu ("Paste and go")
    def _urlbar_context_menu(self, pos):
        from PySide6.QtGui import QGuiApplication
        menu = self.urlbar.createStandardContextMenu()
        clip = QGuiApplication.clipboard().text().strip()
        if clip:
            one_line = clip.splitlines()[0][:48] + ("…" if len(clip) > 48 else "")
            go = QAction(f"Paste and go — {one_line}", menu)
            go.triggered.connect(lambda: (self.urlbar.setText(clip), self.navigate(clip)))
            acts = menu.actions()
            paste = next((a for a in acts if "paste" in a.text().lower()), None)
            if paste is not None:  # place it right after the standard "Paste"
                i = acts.index(paste)
                menu.insertAction(acts[i + 1] if i + 1 < len(acts) else None, go)
            else:
                menu.insertAction(acts[0] if acts else None, go)
        menu.exec(self.urlbar.mapToGlobal(pos))

    # ---------------------------------------------------------------- HTTPS certificate viewer (click the lock)
    def _show_certificate(self):
        v = self.current_view()
        if not v:
            return
        url = v.url()
        if url.scheme() != "https":
            self.toast("This page isn't served over HTTPS — there's no certificate to show.", 4000)
            return
        if self.tor:
            from PySide6.QtWidgets import QMessageBox
            QMessageBox.information(self, "Certificate",
                                    "Certificate inspection is turned off in Tor windows: it needs a direct "
                                    "connection to the site, which would reveal your real IP and break Tor.")
            return
        host, port = url.host(), url.port(443)
        if not host:
            return
        self.toast(f"Fetching certificate for {host}…", 2500)
        self.runner.run(lambda: self._fetch_cert(host, port),
                        lambda ok, res: self._show_cert_dialog(host, ok, res))

    @staticmethod
    def _fetch_cert(host: str, port: int) -> dict:
        """Open a direct TLS connection and return the server certificate's details for display. We don't verify
        (CERT_NONE) on purpose — a pentester wants to SEE an invalid/expired/self-signed cert, not be blocked."""
        import socket
        import ssl
        from datetime import datetime, timezone
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                der = ss.getpeercert(binary_form=True)
                tlsver, cipher = ss.version(), ss.cipher()
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        c = x509.load_der_x509_certificate(der)

        def attr(name, oid):
            try:
                return name.get_attributes_for_oid(oid)[0].value
            except Exception:  # noqa: BLE001
                return ""
        nvb = getattr(c, "not_valid_before_utc", None) or c.not_valid_before
        nva = getattr(c, "not_valid_after_utc", None) or c.not_valid_after
        if nvb.tzinfo is None:
            nvb = nvb.replace(tzinfo=timezone.utc)
        if nva.tzinfo is None:
            nva = nva.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        status = ("Not yet valid" if now < nvb else "EXPIRED" if now > nva
                  else f"Valid — {(nva - now).days} day(s) left")
        try:
            sans = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value \
                .get_values_for_type(x509.DNSName)
        except Exception:  # noqa: BLE001
            sans = []
        pk = c.public_key()
        key = (f"RSA {pk.key_size}-bit" if isinstance(pk, rsa.RSAPublicKey)
               else f"EC {pk.curve.name}" if isinstance(pk, ec.EllipticCurvePublicKey)
               else type(pk).__name__.replace("PublicKey", ""))
        fp = c.fingerprint(hashes.SHA256()).hex().upper()
        fp = ":".join(fp[i:i + 2] for i in range(0, len(fp), 2))
        try:
            sig = c.signature_algorithm_oid._name
        except Exception:  # noqa: BLE001
            sig = ""
        return {"subject_cn": attr(c.subject, x509.NameOID.COMMON_NAME) or c.subject.rfc4514_string(),
                "issuer_cn": attr(c.issuer, x509.NameOID.COMMON_NAME),
                "issuer_org": attr(c.issuer, x509.NameOID.ORGANIZATION_NAME),
                "not_before": nvb.strftime("%Y-%m-%d %H:%M UTC"), "not_after": nva.strftime("%Y-%m-%d %H:%M UTC"),
                "status": status, "sans": sans, "serial": format(c.serial_number, "x"), "sig": sig, "key": key,
                "fp": fp, "tls": tlsver or "", "cipher": (cipher[0] if cipher else ""),
                "pem": c.public_bytes(serialization.Encoding.PEM).decode()}

    def _show_cert_dialog(self, host, ok, res):
        from html import escape
        from PySide6.QtWidgets import QMessageBox
        if not ok or not isinstance(res, dict):
            QMessageBox.warning(self, "Certificate", f"Couldn't fetch the certificate for {host}:\n{res}")
            return
        r = res
        bad = r["status"].startswith(("EXPIRED", "Not yet"))
        status = f"<span style='color:{'#da1e28' if bad else '#0e6027'}'><b>{escape(r['status'])}</b></span>"
        issuer = " · ".join(x for x in (r["issuer_org"], r["issuer_cn"]) if x) or "—"
        sans = ", ".join(r["sans"][:15]) + (" …" if len(r["sans"]) > 15 else "")
        rows = (("Issued by", issuer), ("Status", status), ("Valid", f"{r['not_before']} → {r['not_after']}"),
                ("Alt names", sans or "—"), ("Key", r["key"]), ("Signature", r["sig"]), ("Serial", r["serial"]),
                ("Connection", f"{r['tls']} · {r['cipher']}"))
        body = "<table cellpadding=3>" + "".join(
            f"<tr><td valign=top><b>{escape(k)}</b></td><td>{v if k == 'Status' else escape(str(v))}</td></tr>"
            for k, v in rows)
        body += (f"<tr><td valign=top><b>SHA-256</b></td>"
                 f"<td style='font-family:monospace;font-size:11px'>{escape(r['fp'])}</td></tr></table>")
        box = QMessageBox(self)
        box.setWindowTitle(f"Certificate — {host}")
        box.setTextFormat(Qt.TextFormat.RichText)
        box.setText(f"<b>{escape(r['subject_cn'])}</b>")
        box.setInformativeText(body)
        copy = box.addButton("Copy PEM", QMessageBox.ButtonRole.ActionRole)
        box.addButton(QMessageBox.StandardButton.Close)
        box.exec()
        if box.clickedButton() is copy:
            from PySide6.QtGui import QGuiApplication
            QGuiApplication.clipboard().setText(r["pem"])
            self.toast("Certificate PEM copied to clipboard", 3000)

    # ---------------------------------------------------------------- vertical tabs (left list panel)
    def _apply_tab_orientation(self, vertical: bool):
        """Vertical mode hides the top tab strip and shows the tabs as a readable list on the left (Edge/Arc)."""
        self._vertical_tabs = vertical
        self.tabbar.setVisible(not vertical)
        self.vtabs_panel.setVisible(vertical)
        if vertical:
            self._sync_vtabs()

    def _toggle_vertical_tabs(self):
        self._apply_tab_orientation(not self._vertical_tabs)
        self.settings.setValue("ui/vtabs", self._vertical_tabs)

    def _sync_vtabs(self):
        """Rebuild the left tab list from the real tab bar (titles + favicons)."""
        if not getattr(self, "_vertical_tabs", False):
            return
        lst = self.vtab_list
        self._vtab_syncing = True
        lst.clear()
        for i in range(self.tabbar.count()):
            it = QListWidgetItem(self.tabbar.tabText(i).strip() or "New tab")
            ic = self.tabbar.tabIcon(i)
            if not ic.isNull():
                it.setIcon(ic)
            it.setToolTip(self.tabbar.tabToolTip(i))
            lst.addItem(it)
        lst.setCurrentRow(self.tabbar.currentIndex())
        self._vtab_syncing = False

    def _vtab_update_current(self):
        if getattr(self, "_vertical_tabs", False) and not getattr(self, "_vtab_syncing", False):
            self._vtab_syncing = True
            self.vtab_list.setCurrentRow(self.tabbar.currentIndex())
            self._vtab_syncing = False

    def _vtab_refresh_row(self, view):
        if not getattr(self, "_vertical_tabs", False):
            return
        i = self._index_of(view)
        it = self.vtab_list.item(i) if i >= 0 else None
        if it is not None:
            it.setText((self.tabbar.tabText(i) or "New tab").strip() or "New tab")
            ic = self.tabbar.tabIcon(i)
            if not ic.isNull():
                it.setIcon(ic)

    def _vtab_row_changed(self, row):
        if getattr(self, "_vtab_syncing", False):
            return
        if 0 <= row < self.tabbar.count():
            self.tabbar.setCurrentIndex(row)

    def _vtab_menu(self, pos):
        row = self.vtab_list.indexAt(pos).row()
        m = QMenu(self)
        m.addAction("New tab", self._new_tab_focus)
        if row >= 0:
            m.addAction("Reload", lambda r=row: (self.tabbar.tabData(r).reload() if self.tabbar.tabData(r) else None))
            m.addAction("Duplicate tab", lambda r=row: self.duplicate_tab(r))
            m.addSeparator()
            m.addAction("Close tab", lambda r=row: self.close_tab(r))
        m.exec(self.vtab_list.mapToGlobal(pos))

    # ---------------------------------------------------------------- bookmarks bar (top, like other browsers)
    @staticmethod
    def _bm_title(t: str) -> str:
        t = t or ""
        return (t[:20] + "…") if len(t) > 21 else t

    def _bm_icon_color(self):
        from .. import theme
        return theme.resolve_palette(self.theme_name, self.mode)["icon"]

    def _bm_icon(self, s):
        """A shortcut's favicon (cached), else a generic icon."""
        from PySide6.QtGui import QIcon, QPixmap
        from .. import pages
        dom = pages._sc_domain(s.get("url", ""))
        p = self.data_dir / "shortcut_icons" / (dom + ".img")
        if p.exists():
            pm = QPixmap(str(p))
            if not pm.isNull():
                return QIcon(pm)
        return make_icon("book", self._bm_icon_color())

    def _refresh_bookmarks_bar(self):
        lay = getattr(self, "_bm_layout", None)
        if lay is None:
            return
        while lay.count():
            it = lay.takeAt(0)
            w = it.widget()
            if w:
                w.deleteLater()
        shortcuts = self._shortcuts()
        if not shortcuts:
            hint = QLabel("Right-click to add a bookmark or folder")
            hint.setObjectName("BmHint")
            lay.addWidget(hint)
        for i, s in enumerate(shortcuts):
            btn = QToolButton(objectName="BmBtn")
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
            if isinstance(s.get("items"), list):   # folder → drop-down menu
                btn.setText(self._bm_title(s.get("title") or "Folder"))
                btn.setIcon(make_icon("book", self._bm_icon_color()))
                btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
                btn.setStyleSheet("QToolButton::menu-indicator{image:none;width:0}")
                menu = QMenu(btn)
                for it in s["items"]:
                    menu.addAction(it.get("title") or it.get("url", ""),
                                   lambda _c=False, u=it.get("url", ""): self.open_url(u, new_tab=True))
                if not s["items"]:
                    menu.addAction("(empty)").setEnabled(False)
                menu.addSeparator()
                menu.addAction("Add site to this folder…", lambda _c=False, f=i: self._add_to_folder(f))
                menu.addAction("Remove folder", lambda _c=False, f=i: self._del_shortcut(f))
                btn.setMenu(menu)
                btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                btn.customContextMenuRequested.connect(
                    lambda pos, idx=i, b=btn: self._bm_folder_menu(idx, b, pos))
            else:                                   # plain bookmark
                btn.setText(self._bm_title(s.get("title") or ""))
                btn.setIcon(self._bm_icon(s))
                btn.setToolTip(s.get("url", ""))
                btn.clicked.connect(lambda _c=False, u=s.get("url", ""): self.open_url(u))
                btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
                btn.customContextMenuRequested.connect(
                    lambda pos, idx=i, b=btn: self._bm_item_menu(idx, b, pos))
            lay.addWidget(btn)
        lay.addStretch(1)

    def _bookmarks_bar_menu(self, pos):
        m = QMenu(self)
        m.addAction("Add bookmark…", self._add_shortcut)
        m.addAction("New folder…", self._add_folder)
        m.addSeparator()
        m.addAction("Hide bookmarks bar", self._toggle_bookmarks_bar)
        m.exec(self.bookmarks_bar.mapToGlobal(pos))

    def _bm_item_menu(self, idx, btn, pos):
        m = QMenu(self)
        lst = self._shortcuts()
        url = lst[idx].get("url", "") if 0 <= idx < len(lst) else ""
        m.addAction("Open", lambda: self.open_url(url))
        m.addAction("Open in new tab", lambda: self.open_url(url, new_tab=True))
        m.addSeparator()
        m.addAction("Rename…", lambda: self._rename_shortcut(idx))
        m.addAction("Remove", lambda: self._del_shortcut(idx))
        m.addSeparator()
        m.addAction("Add bookmark…", self._add_shortcut)
        m.addAction("New folder…", self._add_folder)
        m.exec(btn.mapToGlobal(pos))

    def _bm_folder_menu(self, idx, btn, pos):
        lst = self._shortcuts()
        if not (0 <= idx < len(lst)):
            return
        items = lst[idx].get("items") or []
        m = QMenu(self)
        a = m.addAction(f"Open all ({len(items)})", lambda: [self.open_url(it.get("url", ""), new_tab=True)
                                                             for it in items if it.get("url")])
        a.setEnabled(bool(items))
        m.addSeparator()
        m.addAction("Rename…", lambda: self._rename_shortcut(idx))
        m.addAction("Delete folder", lambda: self._del_shortcut(idx))
        m.addSeparator()
        m.addAction("Add page…", lambda: self._add_to_folder(idx))
        m.addAction("Add folder…", self._add_folder)
        m.exec(btn.mapToGlobal(pos))

    def _save_page(self):
        v = self.current_view()
        if v:
            v.page().triggerAction(QWebEnginePage.WebAction.SavePage)

    def _toggle_bookmarks_bar(self):
        vis = not self.settings.value("ui/bookmarks_bar", True, type=bool)
        self._bm_toolbar.setVisible(vis)
        self.settings.setValue("ui/bookmarks_bar", vis)

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
            # The window was already shown with Qt's frameless geometry when the native caption/frame styles
            # were added, so Qt still lays it out with stale frame margins (a dark band above the tab strip)
            # until the first resize/maximize. Nudge the size once so Qt re-measures the client area now.
            QTimer.singleShot(0, self._resync_frame)

    def _resync_frame(self):
        if self.isMaximized() or self.isFullScreen():
            # can't nudge the size; force a non-client recompute so the top frame line is cleared without
            # waiting for the user's first manual resize
            winframe.force_frame_recalc(self)
            return
        w, h = self.width(), self.height()
        self.resize(w, h + 1)
        self.resize(w, h)

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

    def _init_responsive_nav(self):
        """QA-U1: measure the collapsed toolbar and pin the window's minimum width to it, so the nav can never be
        compressed into overlapping widgets. Then lay out for the current width."""
        if not hasattr(self, "_collapsible"):
            return
        for w, _l, _c in self._collapsible:
            w.hide()
        self.b_overflow.show()
        self.nav.layout().activate()
        self.setMinimumWidth(self.nav.minimumSizeHint().width() + 28)
        self._responsive_nav()

    def _responsive_nav(self):
        """Show every tool when there's room; below the breakpoint, move the low-priority ones into the overflow
        menu so nothing overlaps (QA-U1)."""
        if not hasattr(self, "_collapsible"):
            return
        collapse = self.nav.width() < 1180
        self._overflow_menu.clear()
        for widget, label, cb in self._collapsible:
            widget.setVisible(not collapse)
            if collapse:
                self._overflow_menu.addAction(label, cb)
        self.b_overflow.setVisible(collapse)

    def eventFilter(self, obj, ev):
        if obj is getattr(self, "nav", None) and ev.type() == QEvent.Type.Resize:
            self._responsive_nav()
        if obj is getattr(self, "urlbar", None) and ev.type() == QEvent.Type.Resize:
            self.url_icon.move(11, (self.urlbar.height() - self.url_icon.height()) // 2)
            star = getattr(self, "bm_star", None)
            if star is not None:
                star.move(self.urlbar.width() - star.width() - 7, (self.urlbar.height() - star.height()) // 2)
        elif obj is getattr(self, "urlbar", None) and ev.type() == QEvent.Type.FocusIn \
                and ev.reason() == Qt.FocusReason.MouseFocusReason:
            # QA-L4: like Chrome/Firefox, select the whole URL when the bar is first clicked, so typing replaces it
            self._urlbar_click_select = True
        elif obj is getattr(self, "urlbar", None) and ev.type() == QEvent.Type.MouseButtonRelease \
                and getattr(self, "_urlbar_click_select", False):
            self._urlbar_click_select = False
            if not self.urlbar.hasSelectedText():   # respect a click-drag selection the user made
                self.urlbar.selectAll()
        elif obj is getattr(self, "url_icon", None) and ev.type() == QEvent.Type.MouseButtonPress \
                and ev.button() == Qt.MouseButton.LeftButton:
            self._show_certificate()
            return True
        elif obj is getattr(self, "bm_star", None) and ev.type() == QEvent.Type.MouseButtonPress \
                and ev.button() == Qt.MouseButton.LeftButton:
            self._toggle_bookmark_current()
            return True
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
