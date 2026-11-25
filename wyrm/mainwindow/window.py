#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/window.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""The main browser window, composed of focused mixins (see the modules in this package)."""
from __future__ import annotations

import sys
from pathlib import Path

from PySide6.QtCore import QSettings, QStandardPaths, QTimer, QUrl, Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtNetwork import QNetworkInformation
from PySide6.QtWebEngineCore import QWebEngineProfile
from PySide6.QtWidgets import QMainWindow

from .appearance import AppearanceMixin
from .chrome import ChromeMixin
from .docks import DocksMixin
from .downloads import DownloadsMixin
from .engagement import EngagementMixin
from .home import HomeMixin
from .layout import LayoutMixin
from .menu import MenuMixin
from .papers import PapersMixin
from .privacy import PrivacyMixin
from .search import SearchMixin
from .session import SessionMixin
from .browsing_data import BrowsingDataMixin
from .tabs import TabsMixin
from .tor import TorMixin
from .updates import UpdatesMixin
from .extensions import ExtensionsMixin
from .intercept import InterceptMixin
from .capture import CaptureMixin
from .proxy import ProxyMixin
from .. import shields as shields_mod, winframe
from ..async_util import Runner
from ..library import Library
from ..panel import ResearchPanel
from ..scheme import HiddenSchemeHandler
from ..security import rewrite, secsearch
from ..shields import Shields
from ..panels.panel import SecurityPanel
from ..security.store import Store
from ..ui.common import APP, HOME


class MainWindow(
    TabsMixin,
    SearchMixin,
    PrivacyMixin,
    HomeMixin,
    LayoutMixin,
    EngagementMixin,
    AppearanceMixin,
    DocksMixin,
    MenuMixin,
    UpdatesMixin,
    TorMixin,
    ChromeMixin,
    PapersMixin,
    DownloadsMixin,
    SessionMixin,
    BrowsingDataMixin,
    ExtensionsMixin,
    InterceptMixin,
    CaptureMixin,
    ProxyMixin,
    QMainWindow,
):
    def __init__(self, tor=None, private: bool = False, new_window: bool = False):
        super().__init__()
        self._new_window = new_window  # a second window opened in-process (Ctrl+N): blank, doesn't save the session
        self.tor = tor  # TorManager when this is a Tor window
        self.private = bool(private) and not tor  # private window: in-memory profile, nothing saved
        self.ephemeral = bool(tor) or self.private  # Tor and private windows never write browsing data
        self.history_db = None  # browsing history (normal windows only; created once data_dir exists)
        self._set_title(APP + (" (Tor)" if tor else " (Private)" if private else ""))
        self.resize(1440, 900)
        self.setMinimumSize(640, 420)  # keep the tab strip + toolbar from overlapping when shrunk very small
        if winframe.IS_WINDOWS:
            # Qt draws no frame; winframe.install() restores the native resize/snap/shadow behaviour
            self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        elif sys.platform == "darwin":
            # like Safari/Chrome: no separate title bar — the tab strip extends into it and the traffic lights
            # float over its left end; no title text (no WindowTitleHint)
            W = Qt.WindowType
            self.setWindowFlags(W.Window | W.CustomizeWindowHint | W.WindowCloseButtonHint | W.WindowMinimizeButtonHint
                                | W.WindowMaximizeButtonHint | W.WindowFullscreenButtonHint
                                | W.ExpandedClientAreaHint | W.NoTitleBarBackgroundHint)
            self.setWindowFlag(W.WindowTitleHint, False)  # Qt re-adds it; without it the title text is hidden
            # draw right up to the top edge (the tab strip *is* the title bar) instead of below it
            self.setAttribute(Qt.WidgetAttribute.WA_ContentsMarginsRespectsSafeArea, False)
        self.settings = QSettings()
        # F4/F5: move a plain-text AI key out of QSettings into the OS keyring; drop an invalid placeholder model
        from .. import secretstore
        from ..security import triage
        secretstore.migrate(self.settings)
        triage.migrate_model_setting(self.settings)
        self.theme_mode = self.settings.value("theme", "system")
        if self.theme_mode not in ("dark", "light", "hacker", "system"):
            self.theme_mode = "system"
        self.mode = self.settings.value("mode", "blue")  # blue (defensive) | red (offensive)
        if self.mode not in ("blue", "red"):
            self.mode = "blue"
        self.theme_name = self._effective_theme()

        self.data_dir = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        from .. import fileperms
        fileperms.harden(self.data_dir)   # B5: data dir 0700, existing databases/JSON 0600
        if not self.ephemeral:
            from ..history import History
            self.history_db = History(str(self.data_dir / "history.db"))
        self.library = Library(str(self.data_dir / "library.db"))
        self.store = Store(str(self.data_dir / "hidden.db"))
        self.runner = Runner()
        self.shields = Shields(self.data_dir, self.settings)
        self.engagement = None
        self.profiles: dict[str, QWebEngineProfile] = {}
        self._loading_views: set = set()
        self._failed: dict = {}
        self._closed_tabs: list[dict] = []   # recently closed tabs {url, title} (Ctrl+Shift+T / History page)
        self._current_key: str | None = None
        self.block_reasons: dict[str, tuple] = {}  # url -> (category, linkguard verdict) for blocked navigations
        self.http_allowed: set[str] = set()        # hosts the user allowed over plain HTTP this session
        self.upgraded_hosts: set[str] = set()      # hosts HTTPS-Only upgraded (to explain failures)
        self.rules = rewrite.RuleSet([])           # Match & Replace rules for the active engagement
        self.apply_dns()

        self.scheme_handler = HiddenSchemeHandler(self.library, self.runner, self.default_engine, self.home_context, self)
        self.scheme_handler.actions = self.scheme_action
        self.scheme_handler.custom_bg = self._custom_bg
        from ..bgserver import BackgroundVideoServer
        # serves the active background video (uploaded or a bundled loop) over 127.0.0.1 with Range support
        self.bg_video_server = BackgroundVideoServer(self._active_bg_video_path)
        self.scheme_handler.history_page = self._history_page
        self.scheme_handler.bg_cache_dir = self.data_dir / "cache"  # current wallpaper survives restarts

        # docks: security (main) + research (tabbed behind it)
        self.security = SecurityPanel(self)
        self._panel_ratio_timer = QTimer(self, singleShot=True, interval=400)
        self._panel_ratio_timer.timeout.connect(self._panel_resized)
        self.security.installEventFilter(self)  # remember the width the user drags the panel to
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.security)
        self.panel = ResearchPanel(self.library, self)
        self.panel.setWindowTitle("Papers")
        self.panel.open_url.connect(lambda u: self.open_url(u))
        self.panel.save_toggled.connect(lambda *_: self._scan_links(self.current_view()))
        self.panel.rescan.connect(lambda: self._scan_links(self.current_view()))
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, self.panel)
        self.tabifyDockWidget(self.security, self.panel)
        self.panel.hide()
        self.security.setVisible(self.settings.value("sec/visible", True, type=bool))
        self.resizeDocks([self.security], [self._panel_width()], Qt.Orientation.Horizontal)

        last = self.settings.value("engagement", 0, type=int)
        self.engagement = self.store.engagement(last) if last and not tor else None
        self._load_rules()
        self.profile = self._profile_for(self.engagement)
        # Background downloads start once the window is up: Python runs one thread at a time, so starting them
        # during construction slowed the first paint by seconds.
        if self.shields.needs_update():  # refresh filter lists in the background (daily); compiled engines saved
            QTimer.singleShot(5000, lambda: self.runner.run(lambda: shields_mod.build_and_save(self.shields.cache),
                                                            self._filters_ready))
        self._kev_recent: list = []  # latest exploited-in-the-wild CVEs, shown on the start page
        self._news: list = []        # latest cybersecurity headlines, shown on the start page while online
        self._is_online = True
        # keep the bundled ProjectDiscovery tools current: auto-updated copies go to a writable dir
        from ..security import pdtools as _pdt
        _pdt.USER_DIR = self.data_dir / "pdtools-update"
        if not tor:
            QTimer.singleShot(6000, self._update_pd_tools)
            QTimer.singleShot(2500, lambda: self.runner.run(secsearch.recent_kev, self._kev_ready))
            QTimer.singleShot(2500, self._fetch_news)
            self._weather: dict | None = None
            self._geo_place: dict | None = None
            QTimer.singleShot(2800, self._start_weather)
            self._news_timer = QTimer(self)
            self._news_timer.timeout.connect(self._fetch_news)
            self._news_timer.start(30 * 60 * 1000)  # refresh headlines every 30 minutes
            QTimer.singleShot(3200, self._fetch_shortcut_icons)  # favicons for the start-page shortcuts
            if self.settings.value("updates/check", True, type=bool):
                # quiet checks (startup, then every 6 h): a newer release only shows the toolbar "Update" button
                QTimer.singleShot(4000, lambda: self._check_updates(manual=False))
                self._update_timer = QTimer(self)
                self._update_timer.timeout.connect(lambda: self._check_updates(manual=False))
                self._update_timer.start(6 * 60 * 60 * 1000)

        self._build_ui()
        self.update_tls_indicators()   # B7: "Upstream TLS not verified" banner + Proxy panel indicator
        self._setup_dock_titlebars()
        sb = self.statusBar()
        sb.setSizeGripEnabled(False)
        sb.hide()
        sb.messageChanged.connect(lambda m: sb.setVisible(bool(m)))

        if QNetworkInformation.loadBackendByFeatures(QNetworkInformation.Feature.Reachability):
            ni = QNetworkInformation.instance()
            ni.reachabilityChanged.connect(self._on_reachability)
            if ni.reachability() == QNetworkInformation.Reachability.Disconnected:
                self._is_online = False
                QTimer.singleShot(0, lambda: self.offline_banner.set_offline(True))

        geo = self.settings.value("geometry")
        if geo:
            self.restoreGeometry(geo)
        self.apply_theme(self.theme_mode)
        QGuiApplication.styleHints().colorSchemeChanged.connect(
            lambda *_: self.theme_mode == "system" and self.apply_theme("system"))
        self._refresh_engagement_ui()
        if self._new_window:
            self.new_tab(QUrl(HOME))   # a fresh second window starts blank — never restores/clobbers the session
        elif not self._restore_session():
            first_run = not self.ephemeral and not self.settings.value("welcome/seen", False, type=bool)
            if first_run:
                self.settings.setValue("welcome/seen", True)
                self.new_tab(QUrl("wyrm://welcome"))
            else:
                self.new_tab(QUrl(HOME))
        if not self.ephemeral and not self._new_window:  # keep the saved session fresh, so tabs survive a crash
            self._session_timer = QTimer(self)
            self._session_timer.timeout.connect(self._save_session)
            self._session_timer.start(20_000)
        if not self.ephemeral:  # load enabled Wyrm add-ons (never let a broken one block startup)
            try:
                from ..addons import loader as _addon_loader
                _addon_loader.load_all(self)
                self.security.addons_tab._refresh()
            except Exception:  # noqa: BLE001
                pass

    def toast(self, msg: str, ms: int = 5000):
        self.statusBar().showMessage(msg, ms)
