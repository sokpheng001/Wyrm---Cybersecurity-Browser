#------------------------------------------------------------------------------
# Wyrm — wyrm/browser/view.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""BrowserView: one tab's web view (context menu, popups, link hover)."""
from __future__ import annotations

from PySide6.QtGui import QGuiApplication, QKeySequence
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QMenu

from .interceptor import TrafficInterceptor
from .scripts import CAP_PREFIX as _CAP_PREFIX
from .. import engines, linkguard, navpolicy
from ..shields import PageStats


class _CapturePage(QWebEnginePage):
    """Routes the capture script's sentinel console messages to the window; real console logs pass through.
    Also gates page-initiated navigation to privileged/local/script schemes (SEC-10)."""

    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        NT = QWebEnginePage.NavigationType
        user_driven = nav_type in (NT.NavigationTypeTyped, NT.NavigationTypeBackForward, NT.NavigationTypeReload)
        if navpolicy.should_block(url.scheme(), is_main_frame=is_main_frame, user_driven=user_driven,
                                  current_scheme=self.url().scheme()):
            win = getattr(self, "_wyrm_win", None)
            if win is not None and hasattr(win, "toast"):
                win.toast("Blocked a page from opening a restricted address", 4000)
            return False
        return super().acceptNavigationRequest(url, nav_type, is_main_frame)

    def javaScriptConsoleMessage(self, level, message, line, source):
        if message.startswith(_CAP_PREFIX):
            win = getattr(self, "_wyrm_win", None)
            if win is not None and hasattr(win, "_on_capture"):
                # F1: the frame URL comes from Qt, never from what the script claims
                win._on_capture(message[len(_CAP_PREFIX):], self.url().toString())
            return
        super().javaScriptConsoleMessage(level, message, line, source)


class BrowserView(QWebEngineView):
    def __init__(self, win: "MainWindow", popup: bool = False):
        super().__init__()
        self.win = win
        self.popup = popup
        self.stats = PageStats()
        page = _CapturePage(win.profile, self)
        page._wyrm_win = win
        self.setPage(page)
        self.guard = TrafficInterceptor(win, self)
        page.setUrlRequestInterceptor(self.guard)
        page.linkHovered.connect(win.on_link_hovered)
        # track TLS state so the URL bar shows "not secure" on a bad certificate, not a padlock (H-1)
        self.cert_error = False
        page.certificateError.connect(self._on_cert_error)
        self.loadStarted.connect(self._clear_cert_error)

    def _on_cert_error(self, error):
        try:
            if hasattr(error, "isMainFrame") and not error.isMainFrame():
                return  # a sub-resource problem shouldn't flip the whole page to "not secure"
        except Exception:  # noqa: BLE001
            pass
        self.cert_error = True
        try:
            error.rejectCertificate()   # keep Chromium's default: show the certificate-error page
        except Exception:  # noqa: BLE001 — not accepting it rejects by default on some Qt versions
            pass

    def _clear_cert_error(self):
        self.cert_error = False

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
                # two explicit choices: a normal web search, and Wyrm's vulnerability search (not everything
                # selected is a CVE/host, so don't force the security engine just because it's the default)
                web = engines.ENGINES.get(self.win.default_engine())
                if web is None or web.template.startswith("wyrm://"):  # internal engine → use a real web engine
                    web = engines.ENGINES["ddg"]
                menu.addAction(f"Search the web for “{short}”",
                               lambda q=sel, e=web: self.win.open_url(e.url(q), new_tab=True))
                menu.addAction(f"Search vulnerabilities for “{short}”",
                               lambda q=sel: self.win.open_url(engines.SECURITY.url(q), new_tab=True))
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
        # security actions for the current page (Burp/Caido-style quick hand-off to the panel)
        page_url = self.url().toString()
        if page_url.startswith("http"):
            menu.addSeparator()
            menu.addAction("Scan this page (security)", self._scan_this_page)
            menu.addAction("Send page to Repeater", lambda u=page_url: self._send_page_to_repeater(u))
            menu.addAction("Copy as cURL", lambda u=page_url: self._copy_page_curl(u))
        menu.addSeparator()
        menu.addAction("View page source", lambda: self.win.open_url("view-source:" + self.url().toString(), new_tab=True))
        insp = menu.addAction("Inspect", lambda: self.win.inspect(self))
        insp.setShortcut(QKeySequence("Ctrl+Shift+I"))
        menu.exec(event.globalPos())

    def _scan_this_page(self):
        from PySide6.QtCore import QTimer
        try:
            self.win.security.show_tab("Overview")
            QTimer.singleShot(50, self.win.security.overview.analyze_current)
        except Exception:  # noqa: BLE001
            pass

    def _send_page_to_repeater(self, url):
        try:
            self.win.security.tools_tab.load_request("GET", url, {})
            self.win.security.show_tab("Tools")
        except Exception:  # noqa: BLE001
            pass

    def _copy_page_curl(self, url):
        try:
            from ..security import tools
            QGuiApplication.clipboard().setText(tools.to_curl("GET", url, {}))
            self.win.toast("Copied the page request as cURL", 2500)
        except Exception:  # noqa: BLE001
            pass
