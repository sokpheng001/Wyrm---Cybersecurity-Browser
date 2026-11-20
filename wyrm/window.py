"""Wyrm main window: tabs, navigation, engagements/scope, security + research panels."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from PySide6.QtCore import QBuffer, QByteArray, QEvent, QIODevice, QProcess, QSettings, QStandardPaths, Qt, QTimer, QUrl
from PySide6.QtGui import QAction, QActionGroup, QColor, QGuiApplication, QIcon, QKeySequence, QPainter, QPixmap
from PySide6.QtNetwork import QNetworkInformation
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWebEngineCore import (
    QWebEngineGlobalSettings, QWebEngineLoadingInfo, QWebEnginePage, QWebEngineProfile, QWebEngineScript,
    QWebEngineSettings, QWebEngineUrlRequestInterceptor,
)
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import (
    QApplication, QComboBox, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox, QSizePolicy,
    QStackedWidget, QTabBar, QToolBar, QToolButton, QVBoxLayout, QWidget,
)

from . import __version__, engines, linkguard, pages, scholar, theme, winframe
from . import shields as shields_mod
from .security import rewrite, secsearch
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
APP = "Wyrm"
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
    "book": "<path d='M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5z'/><path d='M4 19.5V21h16'/>",
    "search": "<circle cx='11' cy='11' r='7'/><path d='M21 21l-4.3-4.3'/>",
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
        # a link under the cursor → also offer our smart link check + send-to-repeater
        link = data.linkUrl().toString() if data and not data.linkUrl().isEmpty() else ""
        if link:
            menu.addSeparator()
            menu.addAction("Check this link (Smart Link Check)", lambda u=link: self.win.show_link_check(u))
        menu.addSeparator()
        menu.addAction("View page source", lambda: self.win.open_url("view-source:" + self.url().toString(), new_tab=True))
        insp = menu.addAction("Inspect", lambda: self.win.inspect(self))
        insp.setShortcut(QKeySequence("Ctrl+Shift+I"))
        menu.exec(event.globalPos())


class MainWindow(QMainWindow):
    OFFLINE_CODES = {-106, -105, -109, -118, -21, -137, -130}

    def __init__(self, tor=None):
        super().__init__()
        self.tor = tor  # TorManager when this is a Tor window
        self.setWindowTitle(APP + (" (Tor)" if tor else ""))
        self.resize(1440, 900)
        if winframe.IS_WINDOWS:
            # Qt draws no frame; winframe.install() restores the native resize/snap/shadow behaviour
            self.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
        self.settings = QSettings()
        self.theme_mode = self.settings.value("theme", "system")
        if self.theme_mode not in ("dark", "light", "system"):
            self.theme_mode = "system"
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
        self._current_key: str | None = None
        self.block_reasons: dict[str, tuple] = {}  # url -> (category, linkguard verdict) for blocked navigations
        self.http_allowed: set[str] = set()        # hosts the user allowed over plain HTTP this session
        self.upgraded_hosts: set[str] = set()      # hosts HTTPS-Only upgraded (to explain failures)
        self.rules = rewrite.RuleSet([])           # Match & Replace rules for the active engagement
        self.apply_dns()

        self.scheme_handler = HiddenSchemeHandler(self.library, self.runner, self.default_engine, self.home_context, self)
        self.scheme_handler.actions = self.scheme_action

        # docks: security (main) + research (tabbed behind it)
        self.security = SecurityPanel(self)
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
        self.resizeDocks([self.security], [470], Qt.Orientation.Horizontal)

        last = self.settings.value("engagement", 0, type=int)
        self.engagement = self.store.engagement(last) if last and not tor else None
        self._load_rules()
        self.profile = self._profile_for(self.engagement)
        if self.shields.needs_update():  # refresh filter lists in the background (daily)
            self.runner.run(lambda: shields_mod.build_engines(shields_mod.fetch_lists(self.shields.cache)),
                            self._filters_ready)
        self._kev_recent: list = []  # latest exploited-in-the-wild CVEs, shown on the start page
        if not tor:
            self.runner.run(secsearch.recent_kev, self._kev_ready)

        self._build_ui()
        sb = self.statusBar()
        sb.setSizeGripEnabled(False)
        sb.hide()
        sb.messageChanged.connect(lambda m: sb.setVisible(bool(m)))

        if QNetworkInformation.loadBackendByFeatures(QNetworkInformation.Feature.Reachability):
            ni = QNetworkInformation.instance()
            ni.reachabilityChanged.connect(self._on_reachability)
            if ni.reachability() == QNetworkInformation.Reachability.Disconnected:
                QTimer.singleShot(0, lambda: self.offline_banner.set_offline(True))

        geo = self.settings.value("geometry")
        if geo:
            self.restoreGeometry(geo)
        self.apply_theme(self.theme_mode)
        QGuiApplication.styleHints().colorSchemeChanged.connect(
            lambda *_: self.theme_mode == "system" and self.apply_theme("system"))
        self._refresh_engagement_ui()
        self.new_tab(QUrl(HOME))

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
            for i in range(self.tabbar.count()):  # refresh any open start pages so the feed appears
                v = self.tabbar.tabData(i)
                u = v.url()
                if u.scheme() == "wyrm" and u.host() in ("home", ""):
                    v.reload()

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
        self.b_shield.setText(str(n) if n else "")
        host = v.url().host() if v else ""
        off = bool(host) and not self.shields.site_enabled(host)
        self.b_shield.setToolTip(f"Shields: {n} blocked on this page" + (" (Shields are OFF for this site)" if off else ""))
        if self.security.isVisible() and self.security.tabs.currentWidget() is self.security.shields:
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
        """Called by wyrm://allow?... links on warning pages. Returns a URL to continue to."""
        host, url = params.get("host", ""), params.get("url", "")
        if action == "allow-threat" and host:
            self.shields.malware_allow.add(host)
        elif action == "allow-http" and host:
            self.http_allowed.add(host)
            url = "http://" + url.split("://", 1)[-1]
        return url or None

    # ================================================================ helpers used by panels
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
                "saved": self.library.saved(), "kev": self._kev_recent}

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
        app.setStyle("Fusion")
        app.setPalette(theme.palette(name))
        app.setStyleSheet(theme.stylesheet(name, self.data_dir / "ui"))
        p = theme.PALETTES[name]
        pages.THEME = name
        self.loading_bar.COLOR = QColor(p["interactive"])
        ic = p["icon"]
        for btn, icon in self._icon_buttons:
            btn.setIcon(make_icon(icon, p["shell_text"] if btn in self._shell_buttons else ic))
        for act, icon in self._dock_actions:
            act.setIcon(make_icon(icon, ic))
        winframe.set_border_color(self, p["shell"]) if getattr(self, "_frame_installed", False) else None
        self._sync_chrome()
        for i in range(self.tabbar.count()):  # internal pages follow the theme
            view = self.tabbar.tabData(i)
            if view.url().scheme() == "wyrm":
                view.reload()

    def _build_menu(self) -> QMenu:
        m = QMenu(self)
        m.addAction("New tab", self._new_tab_focus, QKeySequence("Ctrl+T"))
        a = m.addAction("New Tor window", self.open_tor_window, QKeySequence("Ctrl+Alt+N"))
        a.setEnabled(not self.tor)
        if self.tor:
            m.addAction("New Tor identity (new circuit)", self.tor_new_identity)
        m.addSeparator()
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
        m.addSeparator()
        m.addAction("About Wyrm", self._about)
        return m

    def _about(self):
        tor = f"<br>Tor {self.tor.version()} · SOCKS port {self.tor.socks_port}" if self.tor else ""
        QMessageBox.about(self, "About Wyrm",
                          f"<b>Wyrm</b> {__version__}<br>"
                          "A <i>wyrm</i> is a wingless dragon — our mark, and the name of this browser.<br><br>"
                          "Built by <b>ByKh R&amp;D Group</b><br><b>HackPi</b> — Ethical Hackers Group<br>"
                          f"Copyright © 2021–2026 HackPi{tor}<br><br>"
                          "Chromium engine via Qt WebEngine · Ad blocking: Brave adblock-rust · Tor: Tor Project")

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

    def _open_settings(self):
        SettingsDialog(self).exec()

    def prompt_restart_for_proxy(self):
        if QMessageBox.question(self, "Restart required",
                                "Proxy settings apply after a restart. Restart now?") == QMessageBox.StandardButton.Yes:
            args = sys.argv[1:] if getattr(sys, "frozen", False) else sys.argv
            QProcess.startDetached(sys.executable, args)
            self.close()

    # ================================================================ chrome
    def _tool(self, icon: str, tip: str, fn=None, keys=()) -> QToolButton:
        b = QToolButton()
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
        self.brand.setContentsMargins(14, 0, 10, 0)
        row.addWidget(self.brand, 0, Qt.AlignmentFlag.AlignVCenter)
        self.tor_tag = tor_tag
        if self.tor:
            row.addWidget(tor_tag, 0, Qt.AlignmentFlag.AlignVCenter)
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
        self.eng_box.setFixedWidth(190)
        self.eng_box.view().setMinimumWidth(280)
        self.eng_box.activated.connect(self._on_engagement_chosen)
        n.addWidget(self.eng_box)
        self.eng_box.setVisible(not self.tor)  # engagements keep persistent sessions; Tor windows never do

        self.urlbar = QLineEdit(objectName="UrlBar")
        self.urlbar.setPlaceholderText("Search, or type a URL, CVE-ID or domain")
        self.urlbar.setFixedHeight(38)
        self.urlbar.setTextMargins(28, 0, 0, 0)  # reserve space for the icon inside the pill
        self.urlbar.returnPressed.connect(lambda: self.navigate(self.urlbar.text()))
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
        self.engine_box.setFixedWidth(200)
        self.engine_box.view().setMinimumWidth(260)  # popup still shows full names
        for key, e in engines.ENGINES.items():
            self.engine_box.addItem(e.name, key)
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
        self.b_shield.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        n.addWidget(self.b_shield)
        self._shield_timer = QTimer(self, singleShot=True, interval=250)
        self._shield_timer.timeout.connect(self._update_shield_button)
        # main menu (like other browsers): new tab / Tor window / theme / settings / about
        self.b_menu = self._tool("more", "Menu")
        self.b_menu.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.b_menu.setMenu(self._build_menu())
        self.b_menu.setStyleSheet("QToolButton::menu-indicator{image:none;width:0}")
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

    def _engine_changed(self):
        self.settings.setValue("search/engine", self.engine_box.currentData())
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

    def navigate(self, text: str):
        url = engines.resolve(text, self.default_engine())
        self.current_view().setUrl(QUrl.fromUserInput(url) if "://" not in url else QUrl(url))
        self.current_view().setFocus()

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
        self.setWindowTitle(prefix + (f"{title} - {APP}" if title and title != "New tab" else APP))

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
        if self.tabbar.count() <= 1:
            self.current_view().setUrl(QUrl(HOME))
            return
        self._remove_tab(i)

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
        if online:
            QTimer.singleShot(800, self._retry_failed)

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
    def _on_download(self, dl):
        folder = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
        dl.setDownloadDirectory(folder)
        dl.accept()
        name = dl.downloadFileName()
        self.toast(f"Downloading {name}…", 0)
        dl.isFinishedChanged.connect(lambda: self.toast(f"Downloaded {os.path.join(folder, name)}", 8000))

    def eventFilter(self, obj, ev):
        if obj is self.urlbar and ev.type() == QEvent.Type.Resize:
            self.url_icon.move(11, (self.urlbar.height() - self.url_icon.height()) // 2)
        return super().eventFilter(obj, ev)

    def keyPressEvent(self, e):
        if e.key() == Qt.Key.Key_Escape and self.current_view():
            self.current_view().stop()
            self._sync_chrome()
        super().keyPressEvent(e)

    def closeEvent(self, e):
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("sec/visible", self.security.isVisible())
        self.runner.shutdown()
        self.tabbar.blockSignals(True)
        while self.tabbar.count():
            view = self.tabbar.tabData(0)
            self.tabbar.removeTab(0)
            view.page().deleteLater()
        super().closeEvent(e)
