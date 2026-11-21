#------------------------------------------------------------------------------
# Wyrm — wyrm/window.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Wyrm main window: tabs, navigation, engagements/scope, security + research panels."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from PySide6.QtCore import (
    QBuffer, QByteArray, QEvent, QIODevice, QObject, QProcess, QSettings, QSize, QStandardPaths, Qt, QTimer, QUrl,
    Signal,
)
from PySide6.QtGui import (
    QAction, QActionGroup, QColor, QGuiApplication, QIcon, QImageReader, QKeySequence, QPainter, QPixmap,
)
from PySide6.QtNetwork import QNetworkInformation
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWebEngineCore import (
    QWebEngineGlobalSettings, QWebEngineLoadingInfo, QWebEnginePage, QWebEngineProfile, QWebEngineScript,
    QWebEngineSettings, QWebEngineUrlRequestInterceptor,
)
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QApplication, QComboBox, QCompleter, QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox,
    QProgressBar, QPushButton, QSizePolicy, QStackedWidget, QTabBar, QTextBrowser, QToolBar, QToolButton, QVBoxLayout,
    QWidget,
)

from html import escape

from . import __build__, __version__, engines, version_label, years, linkguard, pages, scholar, theme, winframe
from . import shields as shields_mod
from .security import news as news_mod, rewrite, secsearch
from .shields import PageStats, Shields
from .async_util import Runner
from .dialogs import EngagementDialog, FindingDialog, SettingsDialog
from .library import Library
from .panel import ResearchPanel
from .scheme import SCHEME, HiddenSchemeHandler
from .security.store import Store
from .security_panel import SecurityPanel
from .widgets import LoadingBar, OfflineBanner

HOME = "wyrm://home"
APP = "Wyrm Browser"
CITESEE_JS = (Path(__file__).with_name("citesee.js")).read_text(encoding="utf-8")
YOUTUBE_JS = (Path(__file__).with_name("youtube.js")).read_text(encoding="utf-8")
FINGERPRINT_JS = (Path(__file__).with_name("fingerprint.js")).read_text(encoding="utf-8")
COLLECT_JS = """JSON.stringify((function(){const c=new Set(),i=new Set();
document.querySelectorAll('[class],[id]').forEach((e,n)=>{if(n>4000)return;
if(e.id)i.add(e.id);if(typeof e.className==='string')e.className.split(/\\s+/).forEach(x=>x&&c.add(x));});
return {classes:[...c].slice(0,3000),ids:[...i].slice(0,3000),yt:window.__hbYtCount||0};})())"""

ICONS = {
    "back": "<path d='M19 12H5'/><path d='M12 19l-7-7 7-7'/>",
    "forward": "<path d='M5 12h14'/><path d='M12 5l7 7-7 7'/>",
    "reload": "<path d='M21 12a9 9 0 1 1-2.64-6.36'/><path d='M21 3v6h-6'/>",
    "stop": "<path d='M18 6L6 18M6 6l12 12'/>",
    "home": "<path d='M3 11l9-8 9 8'/><path d='M5 10v10h5v-6h4v6h5V10'/>",
    "plus": "<path d='M12 5v14M5 12h14'/>",
    "download": "<path d='M12 4v11'/><path d='M7 10l5 5 5-5'/><path d='M5 20h14'/>",
    "book": "<path d='M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5z'/><path d='M4 19.5V21h16'/>",
    "search": "<circle cx='11' cy='11' r='7'/><path d='M21 21l-4.3-4.3'/>",
    "clock": "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
    "lock": "<rect x='5' y='11' width='14' height='10' rx='2'/><path d='M8 11V7a4 4 0 0 1 8 0v4'/>",
    "unlock": "<rect x='5' y='11' width='14' height='10' rx='2'/><path d='M8 11V7a4 4 0 0 1 7.5-2'/>",
    "shield": "<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/><path d='M9 12l2 2 4-4'/>",
    "moon": "<path d='M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z'/>",
    "sun": "<circle cx='12' cy='12' r='4'/><path d='M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4'/>",
    "gear": "<circle cx='12' cy='12' r='3'/><path d='M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z'/>",
    "flag": "<path d='M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z'/><path d='M4 22v-7'/>",
    "win_min": "<path d='M7 12h10'/>",
    "win_max": "<rect x='7' y='7' width='10' height='10'/>",
    "win_restore": "<rect x='7' y='9' width='8' height='8'/><path d='M9 9V7h8v8h-2'/>",
    "win_close": "<path d='M7 7l10 10M17 7L7 17'/>",
    "shields": "<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/><path d='M8 8l8 8'/>",
    "more": "<circle cx='12' cy='5' r='1'/><circle cx='12' cy='12' r='1'/><circle cx='12' cy='19' r='1'/>",
    "monitor": "<rect x='3' y='4' width='18' height='12'/><path d='M8 20h8M12 16v4'/>",
    "onion": "<circle cx='12' cy='13' r='8'/><circle cx='12' cy='13' r='5'/><circle cx='12' cy='13' r='2'/><path d='M12 5V2'/>",
}


def make_icon(name: str, color: str, size: int = 40) -> QIcon:
    svg = (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='{color}' "
           f"stroke-width='1.5' stroke-linecap='square' stroke-linejoin='miter'>{ICONS[name]}</svg>")
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    renderer.render(p)
    p.end()
    return QIcon(pm)


class TrafficInterceptor(QWebEngineUrlRequestInterceptor):
    """Sees every request the engine makes: logs it, checks scope, blocks out-of-scope in strict mode."""

    def __init__(self, win):
        super().__init__(win)
        self.win = win

    """Per-tab request pipeline, in order:
    HTTPS-Only upgrade → tracking-parameter stripping → threat lists (malware/phishing) → smart link check →
    ads/trackers (Brave adblock engine + HackPi heuristics) → engagement scope → traffic log."""

    def __init__(self, win, view):
        super().__init__(view)
        self.win = win
        self.view = view

    def interceptRequest(self, info):
        url = info.requestUrl()
        scheme = url.scheme()
        if scheme not in ("http", "https", "ws", "wss"):
            return
        win, view = self.win, self.view
        host = url.host()
        u = url.toString()
        rtype = info.resourceType().name.replace("ResourceType", "")
        main = rtype == "MainFrame"
        first = info.firstPartyUrl()
        fp_host = host if main else (first.host() or host)
        if main and view.stats.host != host:
            view.stats = PageStats(host=host)
        st = view.stats
        sh = win.shields

        # 1. encrypt: upgrade plain HTTP/WS to HTTPS/WSS (local/lab hosts and user exceptions excluded)
        if scheme in ("http", "ws") and win.https_only() and not linkguard.is_private_host(host) \
                and host not in win.http_allowed:
            nu = QUrl(url)
            nu.setScheme("https" if scheme == "http" else "wss")
            if nu.port() == 80:
                nu.setPort(-1)
            win.upgraded_hosts.add(host)
            st.counts["upgraded"] += 1
            info.redirect(nu)
            return
        # 2. strip click-tracking parameters from navigations
        if main and sh.enabled("params"):
            clean = linkguard.strip_tracking(u)
            if clean != u:
                st.counts["params"] += 1
                info.redirect(QUrl(clean))
                return
        # 3-5. threats, smart link check, ads & trackers
        cat = None
        if host not in sh.malware_allow:
            cat = sh.check(u, first.toString(), rtype, fp_host)
            if main and cat is None and sh.enabled("linkguard"):
                verdict = linkguard.analyze(u)
                # always ask before opening a dangerous OR suspicious link (user preference)
                if verdict["verdict"] in ("dangerous", "suspicious"):
                    cat = "suspicious"
                    win.block_reasons[u] = ("suspicious", verdict)
        if cat is None and not main and sh.enabled("trackers") and sh.site_enabled(fp_host) \
                and linkguard.heuristic_tracker(u, fp_host, rtype):
            cat = "trackers"
        if cat:
            info.block(True)
            key = {"suspicious": "phishing"}.get(cat, cat)
            st.counts[key] = st.counts.get(key, 0) + 1
            st.blocked.append((cat, u, rtype))
            sh.count()
            if main and u not in win.block_reasons:
                win.block_reasons[u] = (cat, linkguard.analyze(u, threat=cat))
            win.on_blocked(view)
        # 6. engagement scope
        eng = win.engagement
        in_scope = eng.in_scope(host) if eng else None
        scope_block = bool(eng and eng.block_out_of_scope and in_scope is False)
        if scope_block and not cat:
            info.block(True)
        # 6b. Match & Replace (pentester): rewrite request headers for in-scope hosts only
        if not cat and in_scope and win.rules.active():
            try:
                cur = {bytes(k).decode(): bytes(v).decode() for k, v in info.httpHeaders().items()}
            except Exception:  # noqa: BLE001
                cur = {}
            for name, val in win.rules.apply(host, cur).items():
                info.setHttpHeader(name.encode(), b"" if val is None else val.encode())
        # 7. log
        try:
            method = bytes(info.requestMethod()).decode()
        except Exception:  # noqa: BLE001
            method = "GET"
        headers = {}
        try:
            headers = {bytes(k).decode(): bytes(v).decode() for k, v in info.httpHeaders().items()}
        except Exception:  # noqa: BLE001 - not available on every Qt version
            pass
        path = url.path() + ("?" + url.query() if url.hasQuery() else "")
        win.security.traffic.add({
            "time": datetime.now().strftime("%H:%M:%S"), "method": method, "type": rtype + (f" [{cat}]" if cat else ""),
            "host": host, "path": path or "/", "url": u, "in_scope": in_scope, "blocked": bool(cat) or scope_block,
            "headers": headers,
        })


class BrowserView(QWebEngineView):
    def __init__(self, win: "MainWindow", popup: bool = False):
        super().__init__()
        self.win = win
        self.popup = popup
        self.stats = PageStats()
        page = QWebEnginePage(win.profile, self)
        self.setPage(page)
        self.guard = TrafficInterceptor(win, self)
        page.setUrlRequestInterceptor(self.guard)
        page.linkHovered.connect(win.on_link_hovered)

    def createWindow(self, _type):  # target=_blank, window.open
        return self.win.new_tab(None, popup=True)

    def contextMenuEvent(self, event):
        page = self.page()
        WA = QWebEnginePage.WebAction
        menu = QMenu(self)
        data = page.contextMenuData() if hasattr(page, "contextMenuData") else None
        # navigation
        for act in (WA.Back, WA.Forward, WA.Reload):
            a = page.action(act)
            if a.isEnabled():
                menu.addAction(a)
        # link / selection / media actions, only when relevant
        for act in (WA.OpenLinkInNewTab, WA.CopyLinkToClipboard, WA.DownloadLinkToDisk, WA.Copy, WA.Paste,
                    WA.CopyImageToClipboard, WA.DownloadImageToDisk, WA.SavePage):
            a = page.action(act)
            if a.isEnabled() and a.text():
                if menu.actions() and menu.actions()[-1].text():
                    pass
                menu.addAction(a)
        # Qt6 exposes the richer request object; fall back to the old data for older builds
        req = self.lastContextMenuRequest() if hasattr(self, "lastContextMenuRequest") else data
        link = ""
        if req is not None and not req.linkUrl().isEmpty():
            link = req.linkUrl().toString()
        sel = (req.selectedText().strip() if req is not None else "")
        editable = bool(req is not None and req.isContentEditable())
        # selection → search it, or go to it if it looks like a URL/domain
        if sel:
            menu.addSeparator()
            looks_url = (sel.startswith(("http://", "https://"))
                         or ("." in sel and " " not in sel and len(sel) < 2048))
            short = sel[:34] + ("…" if len(sel) > 34 else "")
            if looks_url:
                menu.addAction(f"Go to {short}", lambda u=sel: self.win.open_url(engines.resolve(u), new_tab=True))
            else:
                menu.addAction(f"Search “{short}”",
                               lambda q=sel: self.win.open_url(engines.resolve(q), new_tab=True))
        # paste without formatting, for editable fields
        if editable:
            menu.addAction("Paste as plain text", lambda: page.triggerAction(WA.PasteAndMatchStyle))
        # copy a tracker-stripped link (the link under the cursor, or the current page)
        clean_target = link or self.url().toString()
        if clean_target.startswith("http"):
            menu.addAction("Copy clean link (no trackers)",
                           lambda u=clean_target: QGuiApplication.clipboard().setText(linkguard.strip_tracking(u)))
        # a link under the cursor → also offer our smart link check
        if link:
            menu.addSeparator()
            menu.addAction("Check this link (Smart Link Check)", lambda u=link: self.win.show_link_check(u))
        menu.addSeparator()
        menu.addAction("View page source", lambda: self.win.open_url("view-source:" + self.url().toString(), new_tab=True))
        insp = menu.addAction("Inspect", lambda: self.win.inspect(self))
        insp.setShortcut(QKeySequence("Ctrl+Shift+I"))
        menu.exec(event.globalPos())


class Updater(QObject):
    """One-click update (no dialog, no links): download the installer for this OS, then install in place
    (Windows: silent installer; macOS: replace the app and relaunch) and quit. Progress drives the toolbar pill."""
    progress = Signal(int)
    finished = Signal(bool, str)

    def __init__(self, win, info: dict):
        super().__init__(win)
        self.win, self.info = win, info
        self.finished.connect(self._on_finished)

    def start(self) -> bool:
        from . import updater
        url = self.info.get("asset_url")
        if not url:
            return False
        tmp = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.TempLocation))
        dest = tmp / (self.info.get("asset_name") or "wyrm-update.bin")
        px, verify = self.win.proxies(), self.win.verify_tls()

        def work():
            updater.download(url, dest, px, verify, progress=lambda pct, *_: self.progress.emit(pct))
            return str(dest)
        self.win.runner.run(work, lambda ok, res: self.finished.emit(bool(ok), str(res)))
        return True

    def _on_finished(self, ok, res):
        from . import updater
        if not ok:
            self.win._update_failed(f"Download failed: {res}")
            return
        try:
            updater.run_installer(Path(res))
        except Exception as e:  # noqa: BLE001
            self.win._update_failed(f"Could not start the installer: {e}")
            return
        self.win._update_restarting()
        for w in QApplication.topLevelWidgets():  # the installer needs us gone: no "Close Wyrm?" prompt
            w._force_close = True
        QTimer.singleShot(800, QApplication.instance().quit)


class MainWindow(QMainWindow):
    OFFLINE_CODES = {-106, -105, -109, -118, -21, -137, -130}

    def __init__(self, tor=None):
        super().__init__()
        self.tor = tor  # TorManager when this is a Tor window
        self._set_title(APP + (" (Tor)" if tor else ""))
        self.resize(1440, 900)
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
        self.theme_mode = self.settings.value("theme", "system")
        if self.theme_mode not in ("dark", "light", "system"):
            self.theme_mode = "system"
        self.mode = self.settings.value("mode", "blue")  # blue (defensive) | red (offensive)
        if self.mode not in ("blue", "red"):
            self.mode = "blue"
        self.theme_name = self._effective_theme()

        self.data_dir = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation))
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.library = Library(str(self.data_dir / "library.db"))
        self.store = Store(str(self.data_dir / "hidden.db"))
        self.runner = Runner()
        self.shields = Shields(self.data_dir, self.settings)
        self.engagement = None
        self.profiles: dict[str, QWebEngineProfile] = {}
        self._loading_views: set = set()
        self._failed: dict = {}
        self._closed_tabs: list[str] = []   # URLs of recently closed tabs (Ctrl+Shift+T)
        self._current_key: str | None = None
        self.block_reasons: dict[str, tuple] = {}  # url -> (category, linkguard verdict) for blocked navigations
        self.http_allowed: set[str] = set()        # hosts the user allowed over plain HTTP this session
        self.upgraded_hosts: set[str] = set()      # hosts HTTPS-Only upgraded (to explain failures)
        self.rules = rewrite.RuleSet([])           # Match & Replace rules for the active engagement
        self.apply_dns()

        self.scheme_handler = HiddenSchemeHandler(self.library, self.runner, self.default_engine, self.home_context, self)
        self.scheme_handler.actions = self.scheme_action
        self.scheme_handler.custom_bg = self._custom_bg

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
        if self.shields.needs_update():  # refresh filter lists in the background (daily)
            self.runner.run(lambda: shields_mod.build_engines(shields_mod.fetch_lists(self.shields.cache)),
                            self._filters_ready)
        self._kev_recent: list = []  # latest exploited-in-the-wild CVEs, shown on the start page
        self._news: list = []        # latest cybersecurity headlines, shown on the start page while online
        self._is_online = True
        if not tor:
            self.runner.run(secsearch.recent_kev, self._kev_ready)
            self._fetch_news()
            self._news_timer = QTimer(self)
            self._news_timer.timeout.connect(self._fetch_news)
            self._news_timer.start(30 * 60 * 1000)  # refresh headlines every 30 minutes
            if self.settings.value("updates/check", True, type=bool):
                # quiet checks (startup, then every 6 h): a newer release only shows the toolbar "Update" button
                QTimer.singleShot(4000, lambda: self._check_updates(manual=False))
                self._update_timer = QTimer(self)
                self._update_timer.timeout.connect(lambda: self._check_updates(manual=False))
                self._update_timer.start(6 * 60 * 60 * 1000)

        self._build_ui()
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
        if not self._restore_session():
            self.new_tab(QUrl(HOME))
        if not self.tor:  # keep the saved session fresh, so tabs survive even a crash
            self._session_timer = QTimer(self)
            self._session_timer.timeout.connect(self._save_session)
            self._session_timer.start(20_000)

    # ================================================================ privacy: shields, HTTPS-Only, DNS
    def https_only(self) -> bool:
        return self.settings.value("privacy/https_only", True, type=bool)

    DOH = {"cloudflare": ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
           "quad9": ("Quad9 (malware-blocking)", "https://dns.quad9.net/dns-query"),
           "google": ("Google", "https://dns.google/dns-query"),
           "adguard": ("AdGuard (ad-blocking)", "https://dns.adguard-dns.com/dns-query")}

    def apply_dns(self):
        """Encrypted DNS (DNS-over-HTTPS). Tor windows resolve inside Tor instead."""
        if self.tor:
            return
        mode = self.settings.value("privacy/doh_mode", "secure", type=str)  # off | secure (fallback) | strict
        prov = self.settings.value("privacy/doh_provider", "cloudflare", type=str)
        dm = QWebEngineGlobalSettings.DnsMode()
        if mode == "off":
            dm.secureMode = QWebEngineGlobalSettings.SecureDnsMode.SystemOnly
        else:
            dm.secureMode = (QWebEngineGlobalSettings.SecureDnsMode.SecureOnly if mode == "strict"
                             else QWebEngineGlobalSettings.SecureDnsMode.SecureWithFallback)
            dm.serverTemplates = [self.DOH.get(prov, self.DOH["cloudflare"])[1]]
        QWebEngineGlobalSettings.setDnsMode(dm)

    def _kev_ready(self, ok, result):
        if ok and result:
            self._kev_recent = result
            self._refresh_home_pages()

    def _refresh_home_pages(self):
        for i in range(self.tabbar.count()):  # reload open start pages so new feeds / background show up
            v = self.tabbar.tabData(i)
            u = v.url()
            if u.scheme() == "wyrm" and u.host() in ("home", ""):
                v.page().triggerAction(QWebEnginePage.WebAction.ReloadAndBypassCache)

    # ---------------------------------------------------------------- start page: news + background
    def _fetch_news(self):
        if self.tor or not self._is_online:
            return
        self.runner.run(lambda: news_mod.latest(8, self.proxies(), self.verify_tls()), self._news_ready)

    def _news_ready(self, ok, result):
        if ok and result and result != self._news:
            self._news = result
            self._refresh_home_pages()

    BG_DIR = "backgrounds"
    BG_EXTS = {".jpg": b"image/jpeg", ".jpeg": b"image/jpeg", ".png": b"image/png", ".webp": b"image/webp",
               ".gif": b"image/gif"}
    BG_MAX_BYTES = 25 * 1024 * 1024

    def _custom_bg_path(self) -> Path | None:
        d = self.data_dir / self.BG_DIR
        return next((f for f in sorted(d.glob("custom.*")) if f.suffix.lower() in self.BG_EXTS), None) \
            if d.is_dir() else None

    def _custom_bg(self):
        f = self._custom_bg_path()
        try:
            return (f.read_bytes(), self.BG_EXTS[f.suffix.lower()]) if f else None
        except OSError:
            return None

    def _bg_settings(self) -> dict:
        s = self.settings
        mode = s.value("home/bg_mode", "", type=str)
        if mode not in ("random", "color", "image", "none"):  # older versions: a single on/off switch
            mode = "random" if s.value("home/background", True, type=bool) else "none"
        f = self._custom_bg_path()
        ver = str(int(f.stat().st_mtime)) if f else ""
        if mode == "image" and not ver:
            mode = "random"
        return {"mode": mode, "color": s.value("home/bg_color", "midnight", type=str), "image_ver": ver,
                "interval": self._bg_interval()}

    def _bg_interval(self) -> int:
        """Minutes between wallpaper changes (Customize → Change wallpaper every); also applied to pages."""
        mins = self.settings.value("home/bg_interval_min", 30, type=int)
        if mins not in pages.BG_INTERVAL_LABEL:
            mins = 30
        pages.BG_ROTATE_MS = mins * 60 * 1000  # read by the start page timer and the wyrm://bg cache
        return mins

    def _set_background(self, params: dict):
        mode = params.get("mode", "")
        if mode not in ("random", "color", "image", "none"):
            return
        if mode == "color":
            color = params.get("color", "")
            if color not in pages.BG_COLOR_CSS:
                return
            self.settings.setValue("home/bg_color", color)
        self.settings.setValue("home/bg_mode", mode)
        self.settings.setValue("home/background", mode != "none")
        self.settings.sync()
        QTimer.singleShot(0, self._refresh_home_pages)

    def _pick_background_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a background image", str(Path.home() / "Pictures"),
                                              "Images (*.jpg *.jpeg *.png *.webp *.gif)")
        if not path:
            return
        src = Path(path)
        ext = src.suffix.lower()
        try:
            size = src.stat().st_size
        except OSError:
            return
        reader = QImageReader(str(src))
        if ext not in self.BG_EXTS or size > self.BG_MAX_BYTES or not reader.canRead():
            QMessageBox.warning(self, "Background", "Please choose a JPG, PNG, WebP or GIF image up to 25 MB.")
            return
        d = self.data_dir / self.BG_DIR
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("custom.*"):
            old.unlink(missing_ok=True)
        (d / f"custom{ext}").write_bytes(src.read_bytes())
        self._set_background({"mode": "image"})

    def _filters_ready(self, ok, engines_):
        if ok and engines_:
            self.shields.engines = engines_
            self.security.shields.refresh()

    def on_blocked(self, view):
        if view is self.current_view() and not self._shield_timer.isActive():
            self._shield_timer.start()

    def _update_shield_button(self):
        v = self.current_view()
        n = v.stats.total() if v else 0
        badge = self.shield_badge
        badge.setText(str(n) if n < 1000 else "999+")
        badge.adjustSize()
        bw = max(16, badge.width())
        badge.setGeometry(40 - bw - 1, 2, bw, 16)
        badge.setVisible(n > 0)
        host = v.url().host() if v else ""
        off = bool(host) and not self.shields.site_enabled(host)
        self.b_shield.setToolTip(f"Shields: {n} blocked on this page" + (" (Shields are OFF for this site)" if off else ""))
        if self.security.isVisible() and self.security.current_page() is self.security.shields:
            self.security.shields.refresh()

    def on_link_hovered(self, url: str):
        if not url:
            self.link_bubble.hide()
            return
        cat = None
        if url.startswith("http"):
            host = QUrl(url).host()
            cat = self.shields.check(url, url, "MainFrame", host) if host not in self.shields.malware_allow else None
        v = linkguard.analyze(url, threat=cat if cat in ("malware", "phishing") else None)
        p = theme.PALETTES[self.theme_name]
        color = {"dangerous": p["error"], "suspicious": "#ff832b"}.get(v["verdict"])
        text = url if len(url) < 110 else url[:107] + "…"
        if color:
            label = "Dangerous link" if v["verdict"] == "dangerous" else "Suspicious link"
            self.link_bubble.setText(f"<b style='color:{color}'>{label}:</b> {v['reasons'][0]}<br>"
                                     f"<span style='color:{p['muted']}'>{text}</span>")
        else:
            self.link_bubble.setText(text)
        self.link_bubble.adjustSize()
        self.link_bubble.move(8, self.stack.height() - self.link_bubble.height() - 8)
        self.link_bubble.show()
        self.link_bubble.raise_()

    def scheme_action(self, action: str, params: dict) -> str | None:
        """Called by wyrm://allow and wyrm://do links. Returns a URL to continue to (or None)."""
        if action.startswith("do:"):
            do = action[3:]
            if do == "tor":
                self.open_tor_window()
            elif do == "scan":
                self.security.show_tab("Overview")
                QTimer.singleShot(50, self.security.overview.analyze_current)
            elif do == "recon":
                self.security.show_tab("Recon")
                QTimer.singleShot(50, self.security.recon.use_current)
            elif do == "bg" and not self.tor:
                self._set_background(params)
            elif do == "bg-interval" and not self.tor:
                try:
                    mins = int(params.get("min", ""))
                except ValueError:
                    mins = 0
                if mins in pages.BG_INTERVAL_LABEL:
                    self.settings.setValue("home/bg_interval_min", mins)
                    self._bg_interval()
                    QTimer.singleShot(0, self._refresh_home_pages)
            elif do == "bg-upload" and not self.tor:
                QTimer.singleShot(0, self._pick_background_image)  # don't block the scheme request on a dialog
            return None
        host, url = params.get("host", ""), params.get("url", "")
        if action == "allow-threat" and host:
            self.shields.malware_allow.add(host)
        elif action == "allow-http" and host:
            self.http_allowed.add(host)
            url = "http://" + url.split("://", 1)[-1]
        return url or None

    # ================================================================ helpers used by panels
    @staticmethod
    def _shrinkable(box: QComboBox, lo: int, hi: int):
        """Toolbar dropdown that gives way to the address bar when the window is narrow."""
        box.setSizeAdjustPolicy(QComboBox.SizeAdjustPolicy.AdjustToContents)  # full width when there is room…
        box.setMinimumWidth(lo)                                                 # …down to lo when there isn't
        box.setMaximumWidth(hi)
        box.setProperty("wyrm_w", (lo, hi))
        box.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        box.view().setMinimumWidth(max(hi, 260))

    PANEL_MIN, PANEL_MAX, PANEL_RATIO = 360, 760, 0.36

    def _panel_width(self) -> int:
        """Side-panel width that follows the window: the user's share of the window (default 36%),
        360-760 px, and never more than half, so the page always keeps most of the space."""
        ratio = getattr(self, "_panel_ratio", None) or self.settings.value("ui/panel_ratio", self.PANEL_RATIO, type=float)
        ratio = min(0.5, max(0.2, ratio))
        return int(max(self.PANEL_MIN, min(self.PANEL_MAX, self.width() * ratio, self.width() * 0.5)))

    def _panel_resized(self):
        """User dragged the panel edge: remember the new share of the window."""
        sec = self.security
        if getattr(self, "_window_resizing", False) or sec.isFloating() or not sec.isVisible() or self.width() < 600:
            return
        self._panel_ratio = sec.width() / self.width()
        self.settings.setValue("ui/panel_ratio", round(self._panel_ratio, 3))

    def resizeEvent(self, ev):
        super().resizeEvent(ev)
        # toolbar: below ~1250px the profile / engine dropdowns go compact so the address bar keeps its room
        narrow = self.width() < 1250
        for box in (getattr(self, "eng_box", None), getattr(self, "engine_box", None)):
            if box is not None and box.property("wyrm_w"):
                lo, hi = box.property("wyrm_w")
                box.setFixedWidth(lo if narrow else hi)
        sec = getattr(self, "security", None)
        # the docked side panel grows / shrinks with the window, keeping its share of the width
        if sec is not None and sec.isVisible() and not sec.isFloating() and ev.oldSize().width() != self.width():
            self._window_resizing = True
            self.resizeDocks([sec], [self._panel_width()], Qt.Orientation.Horizontal)
            QTimer.singleShot(0, lambda: setattr(self, "_window_resizing", False))

    def default_engine(self) -> str:
        return self.engine_box.currentData() if hasattr(self, "engine_box") else engines.DEFAULT_ENGINE

    def proxies(self):
        if self.tor:  # everything the browser itself fetches also goes through Tor
            p = f"socks5h://127.0.0.1:{self.tor.socks_port}"
            return {"http": p, "https": p}
        s = self.settings
        if not s.value("proxy/enabled", False, type=bool):
            return None
        p = f"http://{s.value('proxy/host', '127.0.0.1')}:{s.value('proxy/port', 8080, type=int)}"
        return {"http": p, "https": p}

    def verify_tls(self) -> bool:
        s = self.settings
        return not (s.value("proxy/enabled", False, type=bool) and s.value("proxy/insecure", True, type=bool))

    def open_url(self, url: str, new_tab: bool = False):
        if new_tab or not self.current_view():
            self.new_tab(QUrl(url))
        else:
            self.current_view().setUrl(QUrl(url))

    def toast(self, msg: str, ms: int = 5000):
        self.statusBar().showMessage(msg, ms)

    def home_context(self) -> dict:
        e = self.engagement
        eng = {"name": e.name, "scope": e.scope, "block": e.block_out_of_scope} if e else None
        name = engines.ENGINES.get(self.default_engine(), engines.ENGINES[engines.DEFAULT_ENGINE]).name
        return {"engagement": eng, "counts": self.store.counts(e.id) if e else {}, "engine_name": name,
                "saved": self.library.saved(), "kev": self._kev_recent, "mode": self.mode,
                "background": (not self.tor) and self._bg_settings()["mode"] != "none",
                "bg": self._bg_settings(), "news": self._news if self._is_online else [],
                "tor": bool(self.tor)}

    # ================================================================ profiles / engagements
    def _profile_for(self, eng) -> QWebEngineProfile:
        key = "tor" if self.tor else (f"eng-{eng.id}" if eng else "personal")
        if key in self.profiles:
            return self.profiles[key]
        if self.tor:
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

    # ================================================================ theme / settings
    def _effective_theme(self) -> str:
        if self.theme_mode in ("dark", "light"):
            return self.theme_mode
        scheme = QGuiApplication.styleHints().colorScheme()
        return "light" if scheme == Qt.ColorScheme.Light else "dark"

    def apply_theme(self, mode: str):
        """mode: 'dark' | 'light' | 'system' (follows the OS setting live)."""
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
        pages.THEME = name
        pages.MODE = self.mode
        self.loading_bar.COLOR = QColor(p["interactive"])
        ic = p["icon"]
        for btn, icon in self._icon_buttons:
            btn.setIcon(make_icon(icon, p["shell_text"] if btn in self._shell_buttons else ic))
        for act, icon in self._dock_actions:
            act.setIcon(make_icon(icon, ic))
        winframe.set_border_color(self, p["shell"]) if getattr(self, "_frame_installed", False) else None
        self._update_mode_chip()
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

    def _dock_titlebar(self, dock, title: str):
        """Custom, clearly-visible title bar for a dock (float + close), replacing Qt's tiny native buttons."""
        bar = QWidget(objectName="DockTitle")
        h = QHBoxLayout(bar)
        h.setContentsMargins(14, 0, 6, 0)
        h.setSpacing(2)
        lbl = QLabel(title, objectName="DockTitleLabel")
        h.addWidget(lbl, 1)
        b_float = QToolButton()
        b_float.setToolTip("Detach into its own window / dock back")
        b_float.clicked.connect(lambda: self._toggle_float(dock))
        b_close = QToolButton(objectName="DockClose")
        b_close.setToolTip("Close panel")
        b_close.clicked.connect(dock.close)
        for b, icon in ((b_float, "win_restore"), (b_close, "win_close")):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setFixedSize(30, 30)
            b.setIconSize(b.iconSize().scaled(18, 18, Qt.AspectRatioMode.KeepAspectRatio))
            self._icon_buttons.append((b, icon))  # recolored by apply_theme
            h.addWidget(b)
        # close X turns white on the red hover (otherwise a dark X on red is hard to read)
        b_close.enterEvent = lambda e, b=b_close: b.setIcon(make_icon("win_close", "#ffffff"))
        b_close.leaveEvent = lambda e, b=b_close: b.setIcon(
            make_icon("win_close", theme.PALETTES[self.theme_name]["icon"]))
        bar.setFixedHeight(42)
        dock.setTitleBarWidget(bar)
        # frame the panel whenever it becomes a separate window (button OR dragged out), so the split is obvious
        dock.topLevelChanged.connect(lambda top, d=dock: self._mark_detached(d, top))

    def _mark_detached(self, dock, floating):
        dock.setProperty("detached", bool(floating))
        dock.style().unpolish(dock)
        dock.style().polish(dock)
        if floating:  # give the detached window a soft drop shadow so it reads as a separate window
            QTimer.singleShot(0, lambda: self._native_window_shadow(dock))

    @staticmethod
    def _native_window_shadow(w):
        """Best-effort native drop shadow for a floating window (Windows DWM). No-op elsewhere."""
        if sys.platform != "win32":
            return
        try:
            import ctypes

            class _MARGINS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_int), ("r", ctypes.c_int), ("t", ctypes.c_int), ("b", ctypes.c_int)]
            hwnd = int(w.winId())
            # a 1px extended frame makes DWM composite a drop shadow around the window
            ctypes.windll.dwmapi.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(_MARGINS(1, 1, 1, 1)))
        except Exception:  # noqa: BLE001 - purely cosmetic
            pass

    def _toggle_float(self, dock):
        floating = not dock.isFloating()
        dock.setFloating(floating)
        if floating:  # give the detached window a comfortable size and center it on the main window
            dock.resize(760, max(640, int(self.height() * 0.8)))
            c = self.geometry().center()
            dock.move(c.x() - dock.width() // 2, c.y() - dock.height() // 2)
            dock.raise_()
            dock.activateWindow()
        self._mark_detached(dock, floating)

    def _setup_dock_titlebars(self):
        self._dock_titlebar(self.security, "Security")
        self._dock_titlebar(self.panel, "Papers")

    def _build_menu(self) -> QMenu:
        m = QMenu(self)
        m.addAction("New tab", self._new_tab_focus, QKeySequence("Ctrl+T"))
        a = m.addAction("New Tor window", self.open_tor_window, QKeySequence("Ctrl+Alt+N"))
        a.setEnabled(not self.tor)
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
        for mode, label in (("system", "Follow system"), ("dark", "Dark"), ("light", "Light")):
            act = tm.addAction(label, lambda md=mode: self.apply_theme(md))
            act.setCheckable(True)
            act.setData(mode)
            act.setChecked(mode == self.theme_mode)
            group.addAction(act)
            self._theme_actions[mode] = act
        m.addSeparator()
        m.addAction("Settings…", self._open_settings, QKeySequence("Ctrl+,"))
        m.addAction("Shields && privacy panel", lambda: self.security.show_tab("Shields"))
        m.addAction("Clear search && address history", self._clear_history_confirm)
        m.addSeparator()
        m.addAction("Help — how to use Wyrm (F1)", self.open_help)
        m.addAction("Check for updates…", self._check_updates)
        m.addAction("About Wyrm Browser", self._about)
        return m

    def open_help(self):
        """Built-in user guide in a new tab."""
        self.open_url("wyrm://help", new_tab=True)

    def _check_updates(self, manual=True):
        from . import updater
        if manual:
            self.toast("Checking for updates…", 3000)
        px, verify = self.proxies(), self.verify_tls()
        self.runner.run(lambda: updater.check(__version__, px, verify, __build__),
                        lambda ok, r: self._updates_checked(ok, r, manual))

    def _updates_checked(self, ok, info, manual):
        if not ok:
            if manual:
                QMessageBox.warning(self, "Updates", f"Could not check for updates:\n{info}")
            return
        if not info.get("newer"):
            self._update_info = None
            self.b_update.hide()  # nothing new: no button
            if manual:
                QMessageBox.information(self, "Updates", f"You're on the latest version ({version_label()}).")
            return
        if getattr(self, "_updater", None):  # already updating
            return
        self._update_info = info
        self.b_update.setText("  Update")
        self.b_update.setEnabled(True)
        from . import updater
        changes = updater.whats_new(info.get("notes", ""))
        tip = (f"<b>Wyrm Browser {escape(info.get('version', ''))}</b> is available (you have {version_label()}).<br>"
               "Click to update — it installs and restarts automatically.")
        if changes:
            tip += "<br><br><b>What's new</b><ul style='margin:4px 0 0 -18px'>" + \
                   "".join(f"<li>{escape(c)}</li>" for c in changes) + "</ul>"
        self.b_update.setToolTip(tip)
        self.b_update.show()
        if manual:
            self.toast(f"Wyrm Browser {info.get('version')} is available — click Update at the top right.", 6000)

    def _open_update(self):
        """Update pill clicked: download + install right away, progress shown on the pill."""
        if not self._update_info or getattr(self, "_updater", None):
            return
        self._updater = Updater(self, self._update_info)
        if not self._updater.start():
            self._updater = None
            self.toast("This update has no installer for your system yet.", 5000)
            return
        self.b_update.setEnabled(False)
        self.b_update.setText("  Updating 0%")
        self._updater.progress.connect(lambda pct: self.b_update.setText(f"  Updating {pct}%"))

    def _update_failed(self, msg: str):
        self._updater = None
        self.b_update.setEnabled(True)
        self.b_update.setText("  Update failed — retry")
        self.toast(msg, 6000)

    def _update_restarting(self):
        self.b_update.setText("  Restarting…")

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

    # ================================================================ Tor
    def open_tor_window(self):
        args = (["--tor"] if getattr(sys, "frozen", False) else [sys.argv[0], "--tor"])
        QProcess.startDetached(sys.executable, args)
        self.toast("Opening a Tor window… connecting to the Tor network can take a minute.")

    def tor_new_identity(self):
        try:
            self.tor.new_identity()
            for i in range(self.tabbar.count()):
                self.tabbar.tabData(i).reload()
            self.toast("New Tor identity: new circuits for all tabs")
        except Exception as e:  # noqa: BLE001
            self.toast(f"Couldn't get a new identity: {e}")

    def disconnect_tor(self):
        """Close the Tor window and tear down the Tor process (the window IS the Tor session)."""
        if not self.tor:
            return
        if QMessageBox.question(self, "Disconnect Tor",
                                "Disconnect from the Tor network and close this private window?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self._force_close = True
            self.close()  # app.aboutToQuit → tor.stop() tears down the Tor process

    def _open_settings(self):
        SettingsDialog(self).exec()

    def prompt_restart_for_proxy(self):
        if QMessageBox.question(self, "Restart required",
                                "Proxy settings apply after a restart. Restart now?") == QMessageBox.StandardButton.Yes:
            args = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv
            QProcess.startDetached(sys.executable, args)
            self._force_close = True
            self.close()

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
        logo = QPixmap(str(Path(__file__).parent / "assets" / "icon.png"))
        if not logo.isNull():
            self.brand.setPixmap(logo.scaled(22, 22, Qt.AspectRatioMode.KeepAspectRatio,
                                             Qt.TransformationMode.SmoothTransformation))
        tor_tag = QLabel(objectName="TorTag")
        if self.tor:
            tor_tag.setText("Tor")
        self.brand.setToolTip("Private Tor window: traffic goes through the Tor network, nothing is saved to disk"
                              if self.tor else "Wyrm")
        self.brand.setContentsMargins(14, 0, 0, 0)
        if sys.platform == "darwin":
            row.addSpacing(64)  # room for the traffic lights (window has no separate title bar on macOS)
            strip.installEventFilter(self)  # drag / double-click the empty strip like a title bar
        row.addWidget(self.brand, 0, Qt.AlignmentFlag.AlignVCenter)
        self.tor_tag = tor_tag
        if self.tor:
            row.addWidget(tor_tag, 0, Qt.AlignmentFlag.AlignVCenter)
        # Red/Blue team mode chip (click to switch)
        # (equal space logo → chip → tabs; the chip draws its own glow margin)
        from .widgets import ModeChip
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
        self.eng_box.setVisible(not self.tor)  # engagements keep persistent sessions; Tor windows never do

        self.urlbar = QLineEdit(objectName="UrlBar")
        self.urlbar.setPlaceholderText("Search, or type a URL, CVE-ID or domain")
        self.urlbar.setFixedHeight(38)
        self.urlbar.setTextMargins(28, 0, 0, 0)  # reserve space for the icon inside the pill
        self.urlbar.returnPressed.connect(lambda: self.navigate(self.urlbar.text()))
        # address-bar autocomplete: history + live search suggestions (Tor windows never record anything)
        from PySide6.QtGui import QStandardItemModel
        self._history = [] if self.tor else list(self.settings.value("history/entries", [], type=list) or [])
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
            (["Escape"], self._stop_current),
            (["Ctrl+F", "F3"], self._show_find),
            (["Ctrl+G"], lambda: self._find_step(True)),
            (["Ctrl+P"], self._print_page),
            (["Ctrl+Shift+Delete"], self._clear_history_confirm),
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

    def _ensure_devtools(self):
        if getattr(self, "devtools_dock", None):
            return
        from PySide6.QtWidgets import QDockWidget
        self.devtools_view = QWebEngineView()
        self.devtools_view.setPage(QWebEnginePage(self.profile, self.devtools_view))
        self.devtools_dock = QDockWidget("Developer Tools", self)
        self.devtools_dock.setObjectName("DevToolsDock")
        self.devtools_dock.setWidget(self.devtools_view)
        self._dock_titlebar(self.devtools_dock, "Developer Tools")
        self.apply_theme(self.theme_mode)  # recolor the new title-bar icons
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.devtools_dock)
        self.resizeDocks([self.devtools_dock], [340], Qt.Orientation.Vertical)

    def _devtools(self):
        v = self.current_view()
        if v:
            self.inspect(v, element=False)

    def inspect(self, view=None, element=True):
        view = view or self.current_view()
        if not view:
            return
        self._ensure_devtools()
        self.devtools_dock.show()
        view.page().setDevToolsPage(self.devtools_view.page())
        if element:
            view.page().triggerAction(QWebEnginePage.WebAction.InspectElement)

    def show_link_check(self, url: str):
        cat = None
        if url.startswith("http"):
            host = QUrl(url).host()
            cat = self.shields.check(url, url, "MainFrame", host) if host not in self.shields.malware_allow else None
        v = linkguard.analyze(url, threat=cat if cat in ("malware", "phishing") else None)
        icon = {"dangerous": QMessageBox.Icon.Critical, "suspicious": QMessageBox.Icon.Warning}.get(
            v["verdict"], QMessageBox.Icon.Information)
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle("Smart Link Check")
        box.setText({"dangerous": "This link looks dangerous.", "suspicious": "This link looks suspicious.",
                     "safe": "No warning signs found."}[v["verdict"]])
        box.setInformativeText(url + ("\n\n• " + "\n• ".join(v["reasons"]) if v["reasons"] else ""))
        box.exec()

    def _load_engine_icons(self):
        """Logo for every engine: our own icons for internal ones, cached site favicons for the rest."""
        from . import favicons
        cache = self.data_dir / "favicons"
        own = {engines.SECURITY.key: "shield", engines.RESEARCH.key: "book"}
        for i in range(self.engine_box.count()):
            key = self.engine_box.itemData(i)
            e = engines.ENGINES.get(key)
            if key in own:
                self.engine_box.setItemIcon(i, make_icon(own[key], "#0f62fe", 32))
                continue
            icon = favicons.cached_icon(cache, key)
            self.engine_box.setItemIcon(i, icon or favicons.monogram(e.name if e else key))
            if icon is None and e and not self.tor:  # fetch once, never from a Tor window
                px, verify = self.proxies(), self.verify_tls()

                def done(ok, data, key=key):
                    ic = favicons.store(cache, key, data) if ok and data else None
                    j = self.engine_box.findData(key)
                    if ic is not None and j >= 0:
                        self.engine_box.setItemIcon(j, ic)
                self.runner.run(lambda h=e.home: favicons.fetch(h, px, verify), done)

    def _engine_changed(self):
        self.settings.setValue("search/engine", self.engine_box.currentData())
        self.settings.sync()  # write now, so the choice survives even an unexpected quit
        v = self.current_view()
        if v and v.url().scheme() == "wyrm" and v.url().host() in ("home", ""):
            v.reload()

    def _new_tab_focus(self):
        self.new_tab(QUrl(HOME))
        QTimer.singleShot(0, self.urlbar.setFocus)

    def _reload_or_stop(self):
        v = self.current_view()
        if v in self._loading_views:
            v.stop()
        elif v in self._failed:
            v.setUrl(self._failed[v])
        else:
            v.reload()

    def _zoom(self, delta: float):
        v = self.current_view()
        if not v:
            return
        z = 1.0 if delta == 0 else min(3.0, max(0.3, round(v.zoomFactor() + delta, 2)))
        v.setZoomFactor(z)
        self.toast(f"Zoom {int(z * 100)}%", 1500)

    def navigate(self, text: str):
        self._record_history(text.strip())
        url = engines.resolve(text, self.default_engine())
        self.current_view().setUrl(QUrl.fromUserInput(url) if "://" not in url else QUrl(url))
        self.current_view().setFocus()

    def _record_history(self, text: str):
        if self.tor or not text or text.startswith("wyrm://"):
            return  # never record in Tor windows or for internal pages
        self._history = [text] + [h for h in self._history if h != text]
        del self._history[500:]  # cap
        self.settings.setValue("history/entries", self._history)

    def clear_history(self):
        self._history = []
        self.settings.setValue("history/entries", [])
        self._rebuild_suggest_model([], [])
        self.toast("Search & address history cleared")

    # ------------------------------------------------------------ address-bar suggestions
    def _rebuild_suggest_model(self, history: list[str], suggestions: list[str]):
        """Populate the completer: recent history first (clock), then search suggestions (magnifier)."""
        from PySide6.QtGui import QStandardItem
        self._suggest_model.clear()
        seen = set()
        p = theme.PALETTES[self.theme_name]
        hist_icon = make_icon("clock", p["muted"], 32)
        sugg_icon = make_icon("search", p.get("interactive", p["muted"]), 32)
        for text, icon in [(h, hist_icon) for h in history] + [(s, sugg_icon) for s in suggestions]:
            key = text.lower()
            if not text or key in seen:
                continue
            seen.add(key)
            it = QStandardItem(icon, text)
            it.setEditable(False)
            self._suggest_model.appendRow(it)

    def _fetch_suggestions(self):
        from . import suggest
        q = self.urlbar.text().strip()
        hist = [h for h in self._history if q.lower() in h.lower()][:6]
        # don't query the network for empty text, internal pages, or a complete URL being typed
        if self.tor or len(q) < 2 or q.startswith("wyrm://") or "://" in q:
            self._rebuild_suggest_model(hist, [])
            if q:
                self._completer.complete()
            return

        def done(ok, res):
            if self.urlbar.text().strip() != q:
                return  # user kept typing; a newer request will answer
            sugg = res if ok and isinstance(res, list) else []
            self._rebuild_suggest_model(hist, sugg)
            self._completer.complete()
        self.runner.run(lambda: suggest.fetch(q, self.proxies()), done)

    # ================================================================ tabs
    def current_view(self) -> BrowserView | None:
        i = self.tabbar.currentIndex()
        return self.tabbar.tabData(i) if i >= 0 else None

    def _index_of(self, view) -> int:
        for i in range(self.tabbar.count()):
            if self.tabbar.tabData(i) is view:
                return i
        return -1

    def new_tab(self, url: QUrl | None, popup: bool = False) -> BrowserView:
        view = BrowserView(self, popup=popup)
        self.stack.addWidget(view)
        idx = self.tabbar.addTab("New tab")
        self.tabbar.setTabData(idx, view)
        self.tabbar.setCurrentIndex(idx)
        self.stack.setCurrentWidget(view)
        view.titleChanged.connect(lambda t, v=view: self._set_tab_text(v, t))
        view.iconChanged.connect(lambda ic, v=view: self.tabbar.setTabIcon(self._index_of(v), ic))
        view.urlChanged.connect(lambda u, v=view: v is self.current_view() and self._sync_chrome())
        view.loadStarted.connect(lambda v=view: self._loading(v, True))
        view.loadProgress.connect(lambda p, v=view: v is self.current_view() and self.loading_bar.set_progress(p))
        view.loadFinished.connect(lambda ok, v=view: self._on_load_finished(v, ok))
        view.page().loadingChanged.connect(lambda info, v=view: self._on_loading_info(v, info))
        if url is not None:
            view.setUrl(url)
        return view

    def _loading(self, view, on: bool):
        (self._loading_views.add if on else self._loading_views.discard)(view)
        if view is not self.current_view():
            return
        self.loading_bar.start() if on else self.loading_bar.finish()
        self.b_reload.setIcon(make_icon("stop" if on else "reload", theme.PALETTES[self.theme_name]["icon"]))

    def _set_tab_text(self, view, title):
        i = self._index_of(view)
        if i >= 0:
            self.tabbar.setTabText(i, title or "New tab")
            self.tabbar.setTabToolTip(i, title)
            if view is self.current_view():
                self._set_window_title(title)

    def _set_window_title(self, title: str):
        prefix = f"[{self.engagement.name}] " if self.engagement else ""
        self._set_title(prefix + (f"{title} - {APP}" if title and title != "New tab" else APP))

    def _remove_tab(self, i):
        view = self.tabbar.tabData(i)
        self._failed.pop(view, None)
        self._loading_views.discard(view)
        self.tabbar.removeTab(i)
        self.stack.removeWidget(view)
        view.deleteLater()

    def close_tab(self, i: int):
        if i < 0:
            return
        view = self.tabbar.tabData(i)
        if view is not None and not self.tor:  # remember it for Ctrl+Shift+T (never in Tor windows)
            u = view.url().toString()
            if u and not u.startswith("wyrm://"):
                self._closed_tabs.append(u)
                del self._closed_tabs[:-25]
        if self.tabbar.count() <= 1:
            self.current_view().setUrl(QUrl(HOME))
            return
        self._remove_tab(i)

    def reopen_closed_tab(self):
        if self._closed_tabs:
            self.new_tab(QUrl(self._closed_tabs.pop()))

    def _cycle_tab(self, step: int):
        n = self.tabbar.count()
        if n:
            self.tabbar.setCurrentIndex((self.tabbar.currentIndex() + step) % n)

    def _goto_tab(self, i: int):
        if 0 <= i < self.tabbar.count():
            self.tabbar.setCurrentIndex(i)

    def _stop_current(self):
        v = self.current_view()
        if v and v in self._loading_views:
            v.stop()

    def _toggle_fullscreen(self):
        self.showNormal() if self.isFullScreen() else self.showFullScreen()

    def _print_page(self):
        v = self.current_view()
        if not v:
            return
        from PySide6.QtPrintSupport import QPrintDialog, QPrinter
        printer = QPrinter()
        if QPrintDialog(printer, self).exec():
            v.page().print(printer, lambda ok: self.toast("Printed" if ok else "Print failed"))

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

    def _on_tab_changed(self, _i):
        v = self.current_view()
        if not v:
            return
        self.stack.setCurrentWidget(v)
        self._sync_chrome()
        self._set_window_title(v.title())
        self.loading_bar.reset()
        if v in self._loading_views:
            self.loading_bar.start()
        self.b_reload.setIcon(make_icon("stop" if v in self._loading_views else "reload",
                                        theme.PALETTES[self.theme_name]["icon"]))
        self._update_shield_button()
        self._analyze_paper(v, count_visit=False)

    def _sync_chrome(self):
        v = self.current_view()
        if not v:
            return
        url = self._failed.get(v) or v.url()
        u = url.toString()
        if url.scheme() == "wyrm" and url.host() == "search":
            self.urlbar.setText("!r " + parse_qs(urlparse(u).query).get("q", [""])[0])
        elif url.scheme() == "wyrm" and url.host() == "sec":
            self.urlbar.setText(parse_qs(urlparse(u).query).get("q", [""])[0])
        elif url.scheme() == "wyrm":
            self.urlbar.setText("")
        else:
            self.urlbar.setText(u)
        self.urlbar.setCursorPosition(0)
        p = theme.PALETTES[self.theme_name]
        icon = {"https": "lock", "http": "unlock"}.get(url.scheme(), "search")
        self.url_icon.setPixmap(make_icon(icon, p["error"] if icon == "unlock" else p["muted"]).pixmap(18, 18))
        self.url_icon.setToolTip({"lock": "Secure connection (HTTPS)", "unlock": "Not secure (plain HTTP)"}.get(icon, ""))
        h = v.history()
        self.b_back.setEnabled(h.canGoBack())
        self.b_fwd.setEnabled(h.canGoForward())
        self._update_scope_badge()

    # ================================================================ errors / offline
    def _on_loading_info(self, view, info):
        status = info.status()
        if status == QWebEngineLoadingInfo.LoadStatus.LoadStartedStatus:
            if not info.url().toString().startswith("data:"):
                self._failed.pop(view, None)
        elif status == QWebEngineLoadingInfo.LoadStatus.LoadFailedStatus:
            code = info.errorCode()
            D = QWebEngineLoadingInfo.ErrorDomain
            if code == -3 or info.errorDomain() in (D.HttpStatusCodeDomain, D.NoErrorDomain):
                return  # user pressed stop, or the server sent its own error page: show it as-is
            url = info.url().toString()
            host = info.url().host()
            self._failed[view] = QUrl(url)
            reason = self.block_reasons.pop(url, None)
            if reason:  # blocked by Shields / smart link check: explain why, offer a way through
                self._failed.pop(view, None)
                view.setHtml(pages.render_threat(url, reason[0], reason[1]), QUrl("data:text/html,blocked"))
                return
            if info.url().scheme() == "https" and host in self.upgraded_hosts and code not in self.OFFLINE_CODES:
                view.setHtml(pages.render_https_unavailable(url), QUrl("data:text/html,https"))
                return
            eng = self.engagement
            if eng and eng.block_out_of_scope and eng.in_scope(host) is False:
                code = -20  # blocked by our scope guard (engine reports a generic access error)
            offline = code in self.OFFLINE_CODES and not self._online()
            html = pages.render_error(url, info.errorString() or "", code, offline,
                                      self.engagement.name if self.engagement else None)
            view.setHtml(html, QUrl("data:text/html,error"))
            if offline:
                self.offline_banner.set_offline(True)

    def _online(self) -> bool:
        ni = QNetworkInformation.instance()
        if not ni:
            return True
        return ni.reachability() in (QNetworkInformation.Reachability.Online, QNetworkInformation.Reachability.Unknown)

    def _on_reachability(self, r):
        online = r != QNetworkInformation.Reachability.Disconnected
        self.offline_banner.set_offline(not online)
        was, self._is_online = self._is_online, online
        if online:
            QTimer.singleShot(800, self._retry_failed)
            if not was:
                QTimer.singleShot(1500, self._fetch_news)  # back online: get fresh headlines
        elif was and self._news:
            self._refresh_home_pages()  # offline: hide the news section

    def _retry_failed(self):
        for view, url in list(self._failed.items()):
            view.setUrl(url)

    # ================================================================ per-page features
    def _apply_cosmetics(self, view):
        """Element hiding: list-based selectors for this URL + generic class/id selectors found on the page."""
        url = view.url().toString()
        host = view.url().host()
        if not url.startswith("http") or not self.shields.site_enabled(host):
            return
        css = self.shields.cosmetic_css(url)

        def got(res, v=view, css=css, url=url):
            try:
                d = json.loads(res) if isinstance(res, str) else {}
            except ValueError:
                d = {}
            full = css + self.shields.generic_css(d.get("classes", []), d.get("ids", []), url)
            if full:
                v.page().runJavaScript(
                    "(function(c){let s=document.getElementById('__hb_hide');if(!s){s=document.createElement('style');"
                    "s.id='__hb_hide';(document.head||document.documentElement).appendChild(s);}s.textContent=c;})("
                    + json.dumps(full) + ")", QWebEngineScript.ScriptWorldId.ApplicationWorld)
            yt = int(d.get("yt") or 0)
            if yt > v.stats.counts.get("youtube", 0):
                v.stats.counts["youtube"] = yt
                self.on_blocked(v)
        view.page().runJavaScript(COLLECT_JS, QWebEngineScript.ScriptWorldId.MainWorld, got)

    def _check_popup(self, view):
        """Close pop-ups/pop-unders whose first URL is an ad, tracker or threat."""
        url = view.url().toString()
        if not url.startswith("http"):
            return
        cat = self.shields.check_popup(url)
        if cat:
            opener = self.current_view()
            i = self._index_of(view)
            if i >= 0 and self.tabbar.count() > 1:
                self._remove_tab(i)
            target = opener if opener is not view else self.current_view()
            if target:
                target.stats.counts["popups"] += 1
                target.stats.blocked.append(("popup", url, "Popup"))
                self.shields.count()
                self.on_blocked(target)
            self.toast(f"Blocked a pop-up ({cat}): {QUrl(url).host()}")

    def _on_load_finished(self, view, ok):
        if view.popup:
            view.popup = False
            self._check_popup(view)
        if ok:
            self._apply_cosmetics(view)
            QTimer.singleShot(4000, lambda v=view: self._index_of(v) >= 0 and self._apply_cosmetics(v))  # late content
        if view is self.current_view():
            self._update_shield_button()
            self._loading(view, False)
            self._sync_chrome()
            self._analyze_paper(view, count_visit=True)
            if view not in self._failed:
                self.security.overview.page_loaded(view)

    def _analyze_paper(self, view, count_visit: bool):
        url = view.url().toString()
        key = scholar.paper_key_from_url(url)
        self._current_key = key
        if key:
            if count_visit:
                self.library.record_visit(key, url)
            rec = self.library.get(key)
            if rec and rec.get("meta"):
                self.panel.show_paper(rec["meta"], key)
            else:
                self.panel.show_loading(key)
                self.runner.run(scholar.fetch_paper, lambda ok, res, k=key: self._meta_ready(k, ok, res), key)
        else:
            self.panel.show_paper(None)
        if self.panel.isVisible():
            self._scan_links(view)

    def _meta_ready(self, key, ok, res):
        if ok:
            self.library.update_meta(key, res)
            if self._current_key == key:
                self.panel.show_paper(res, key)
        else:
            self.panel.show_error(key, str(res))

    def _scan_links(self, view):
        if not view:
            return
        js = CITESEE_JS.replace("__KNOWN__", json.dumps(self.library.status_map()))
        view.page().runJavaScript(
            js, QWebEngineScript.ScriptWorldId.ApplicationWorld,
            lambda res, v=view: v is self.current_view() and self.panel.show_page_papers(self._parse(res)))

    @staticmethod
    def _parse(res) -> list[dict]:
        if isinstance(res, list):
            return res
        try:
            return json.loads(res) if res else []
        except (TypeError, ValueError):
            return []

    # ================================================================ downloads / lifecycle
    RISKY_EXT = {".exe", ".msi", ".msix", ".bat", ".cmd", ".com", ".scr", ".pif", ".ps1", ".vbs", ".vbe",
                 ".js", ".jse", ".jar", ".hta", ".cpl", ".dll", ".apk", ".dmg", ".pkg", ".deb", ".rpm",
                 ".sh", ".run", ".reg", ".lnk", ".iso", ".img"}

    def _on_download(self, dl):
        from pathlib import PurePosixPath
        url = dl.url().toString()
        name = dl.downloadFileName()
        host = dl.url().host()
        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else \
              ("." + PurePosixPath(dl.url().path()).suffix.lstrip(".").lower() if PurePosixPath(dl.url().path()).suffix else "")
        # 1. threat check: is the download source a known malware/phishing host?
        threat = self.shields.check(url, url, "MainFrame", host) if host not in self.shields.malware_allow else None
        risky = ext in self.RISKY_EXT
        if threat in ("malware", "phishing"):
            m = QMessageBox(self)
            m.setIcon(QMessageBox.Icon.Critical)
            m.setWindowTitle("Dangerous download blocked")
            m.setText(f"<b>{escape(name)}</b> is being downloaded from <b>{escape(host)}</b>, which is on a "
                      f"{threat} blocklist.")
            m.setInformativeText("This file may be malware. Downloading is strongly discouraged.")
            keep = m.addButton("Download anyway", QMessageBox.ButtonRole.DestructiveRole)
            m.addButton("Block", QMessageBox.ButtonRole.RejectRole)
            m.setDefaultButton(m.buttons()[-1])
            m.exec()
            if m.clickedButton() is not keep:
                dl.cancel()
                self.toast(f"Blocked download from {host} ({threat})")
                return
        elif risky:
            insecure = dl.url().scheme() == "http"
            m = QMessageBox(self)
            m.setIcon(QMessageBox.Icon.Warning)
            m.setWindowTitle("Keep this file?")
            m.setText(f"<b>{escape(name)}</b> is an executable or script that can run code on your computer.")
            m.setInformativeText(f"Source: {escape(host or url)}"
                                 + ("<br><b>Served over plain HTTP — it could be tampered with in transit.</b>" if insecure else "")
                                 + "<br><br>Only keep it if you trust the source. You can verify it on VirusTotal after.")
            keep = m.addButton("Keep", QMessageBox.ButtonRole.AcceptRole)
            m.addButton("Discard", QMessageBox.ButtonRole.RejectRole)
            m.exec()
            if m.clickedButton() is not keep:
                dl.cancel()
                return
        folder = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
        dl.setDownloadDirectory(folder)
        dl.accept()
        self.toast(f"Downloading {name}…", 0)
        dl.isFinishedChanged.connect(lambda d=dl, n=name, f=folder, rk=risky: self._download_finished(d, n, f, rk))

    def _download_finished(self, dl, name, folder, risky):
        from PySide6.QtWebEngineCore import QWebEngineDownloadRequest as DR
        if dl.state() != DR.DownloadState.DownloadCompleted:
            return
        path = os.path.join(folder, name)
        if risky:  # offer a VirusTotal hash check (no file is uploaded — we look up the SHA-256)
            self.runner.run(lambda p=path: self._sha256(p), lambda ok, h: self._offer_vt(name, h) if ok else None)
        else:
            self.toast(f"Downloaded {path}", 8000)

    @staticmethod
    def _sha256(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def _offer_vt(self, name, digest):
        m = QMessageBox(self)
        m.setIcon(QMessageBox.Icon.Information)
        m.setWindowTitle("Download finished")
        m.setText(f"<b>{escape(name)}</b> downloaded.")
        m.setInformativeText("It's an executable. Check its reputation on VirusTotal before running?")
        vt = m.addButton("Check on VirusTotal", QMessageBox.ButtonRole.AcceptRole)
        m.addButton("Not now", QMessageBox.ButtonRole.RejectRole)
        m.exec()
        if m.clickedButton() is vt:
            self.open_url(f"https://www.virustotal.com/gui/file/{digest}", new_tab=True)

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

    # ---------------------------------------------------------------- session (reopen tabs) + close confirmation
    def _session_urls(self) -> list[str]:
        urls = []
        for i in range(self.tabbar.count()):
            u = self.tabbar.tabData(i).url().toString()
            if u and u != "about:blank" and not u.startswith(("data:", "view-source:")):
                urls.append(u)
        return urls

    def _save_session(self):
        if self.tor:
            return  # Tor windows never leave a trace
        self.settings.setValue("session/tabs", json.dumps(self._session_urls()))
        self.settings.setValue("session/current", self.tabbar.currentIndex())
        self.settings.sync()

    def _restore_session(self) -> bool:
        if self.tor:
            return False
        try:
            urls = [u for u in json.loads(self.settings.value("session/tabs", "[]") or "[]") if isinstance(u, str)]
        except ValueError:
            urls = []
        if not urls:
            return False
        for u in urls[:50]:
            self.new_tab(QUrl(u))
        cur = self.settings.value("session/current", 0, type=int)
        if 0 <= cur < self.tabbar.count():
            self.tabbar.setCurrentIndex(cur)
        return True

    def _set_title(self, text: str):
        # macOS: the tab strip is the title bar, so no title text is drawn there. (A single space, because Qt
        # substitutes the app name for an empty title.) Other OSes: normal window title for the taskbar.
        self.setWindowTitle(" " if sys.platform == "darwin" else text)

    def _confirm_close(self) -> bool:
        if getattr(self, "_force_close", False) or not self.settings.value("ui/confirm_close", True, type=bool):
            return True
        from PySide6.QtWidgets import QCheckBox
        n = self.tabbar.count()
        box = QMessageBox(self)
        box.setWindowTitle("Close Wyrm Browser")
        box.setIcon(QMessageBox.Icon.Question)
        if self.tor:
            box.setText("Close this Tor window?")
            box.setInformativeText(f"{n} tab(s) will be closed. Nothing from this private window is saved.")
        else:
            box.setText("Close Wyrm Browser?")
            box.setInformativeText(f"You have {n} tab{'s' if n != 1 else ''} open. "
                                   "They'll be reopened the next time you start Wyrm Browser.")
        dont = QCheckBox("Don't ask again")
        box.setCheckBox(dont)
        close_btn = box.addButton("Close", QMessageBox.ButtonRole.AcceptRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.setDefaultButton(close_btn)
        box.exec()
        if box.clickedButton() is not close_btn:
            return False
        if dont.isChecked():
            self.settings.setValue("ui/confirm_close", False)
        return True

    def closeEvent(self, e):
        if not self._confirm_close():
            e.ignore()
            return
        self._save_session()
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("sec/visible", self.security.isVisible())
        self.runner.shutdown()
        self.tabbar.blockSignals(True)
        while self.tabbar.count():
            view = self.tabbar.tabData(0)
            self.tabbar.removeTab(0)
            view.page().deleteLater()
        super().closeEvent(e)
