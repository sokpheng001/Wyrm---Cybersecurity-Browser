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
from .. import engines, linkguard
from ..shields import PageStats


_CAP_PREFIX = "[[WYRMCAP]]"


class _CapturePage(QWebEnginePage):
    """Routes the capture script's sentinel console messages to the window; real console logs pass through."""
    def javaScriptConsoleMessage(self, level, message, line, source):
        if message.startswith(_CAP_PREFIX):
            win = getattr(self, "_wyrm_win", None)
            if win is not None and hasattr(win, "_on_capture"):
                win._on_capture(message[len(_CAP_PREFIX):])
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
