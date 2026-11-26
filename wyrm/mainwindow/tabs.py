#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/tabs.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Tabs, navigation state, loading, find bar helpers and offline handling."""
from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from PySide6.QtCore import QTimer, QUrl
from PySide6.QtNetwork import QNetworkInformation
from PySide6.QtWebEngineCore import QWebEngineLoadingInfo

from .. import pages, theme
from ..browser.view import BrowserView
from ..ui.common import APP, HOME, make_icon


class TabsMixin:
    """Tabs, navigation state, loading, find bar helpers and offline handling. (Mixed into MainWindow.)"""

    OFFLINE_CODES = {-106, -105, -109, -118, -21, -137, -130}

    def open_url(self, url: str, new_tab: bool = False):
        if new_tab or not self.current_view():
            self.new_tab(QUrl(url))
        else:
            self.current_view().setUrl(QUrl(url))

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
        self._wire_view(view)
        self._sync_vtabs()   # keep the left tab list (if shown) in step
        if url is not None:
            view.setUrl(url)
        return view

    def _wire_view(self, view):
        """Connect a view's signals to THIS window. Connections are stored on the view so they can be cleanly
        detached again when the tab is moved to another window (tab tear-off / merge)."""
        view._win_conns = [
            view.titleChanged.connect(lambda t, v=view: self._set_tab_text(v, t)),
            view.iconChanged.connect(lambda ic, v=view: (self.tabbar.setTabIcon(self._index_of(v), ic),
                                                         self._vtab_refresh_row(v))),
            view.urlChanged.connect(lambda u, v=view: v is self.current_view() and self._sync_chrome()),
            view.loadStarted.connect(lambda v=view: self._loading(v, True)),
            view.loadProgress.connect(lambda p, v=view: v is self.current_view()
                                      and self.loading_bar.set_progress(p)),
            view.loadFinished.connect(lambda ok, v=view: self._on_load_finished(v, ok)),
            view.page().loadingChanged.connect(lambda info, v=view: self._on_loading_info(v, info)),
        ]

    def _unwire_view(self, view):
        """Drop the window-bound signal connections made by _wire_view (the view keeps its own internal ones)."""
        from PySide6.QtCore import QObject
        for c in getattr(view, "_win_conns", []):
            try:
                QObject.disconnect(c)
            except (RuntimeError, TypeError):
                pass
        view._win_conns = []

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

    def _hard_reload(self):
        """Reload the current page bypassing the HTTP cache (Ctrl+Shift+R / Chrome's hard refresh): re-fetch
        every resource from the network, useful after editing a site or when a stale asset is cached."""
        self._hard_reload_view(self.current_view())

    def _hard_reload_view(self, v):
        from PySide6.QtWebEngineCore import QWebEnginePage
        if v is None:
            return
        if v in self._failed:
            v.setUrl(self._failed[v])   # error page has nothing cached to bypass; just retry the URL
            return
        v.page().triggerAction(QWebEnginePage.WebAction.ReloadAndBypassCache)

    def _zoom(self, delta: float):
        v = self.current_view()
        if not v:
            return
        z = 1.0 if delta == 0 else min(3.0, max(0.3, round(v.zoomFactor() + delta, 2)))
        v.setZoomFactor(z)
        pct = int(round(z * 100))
        self.toast(f"Zoom {pct}%", 1500)
        lbl = getattr(self, "_zoom_pct_lbl", None)
        if lbl is not None:
            lbl.setText(f"{pct}%")

    def _loading(self, view, on: bool):
        (self._loading_views.add if on else self._loading_views.discard)(view)
        if on:
            from ..shields import PageStats
            view.stats = PageStats()   # new page → reset the per-tab blocked counter, whatever the scheme (M-6)
        if view is not self.current_view():
            return
        if on:
            c = self.urlbar.completer()        # a navigation started → close the address-bar suggestion popup
            if c is not None:
                c.popup().hide()
            self._shield_timer.start()         # refresh the Shields badge for the new (empty) page
        self.loading_bar.start() if on else self.loading_bar.finish()
        self.b_reload.setIcon(make_icon("stop" if on else "reload", theme.PALETTES[self.theme_name]["icon"]))

    def _set_tab_text(self, view, title):
        i = self._index_of(view)
        if i >= 0:
            muted = view.page().isAudioMuted()
            self.tabbar.setTabText(i, ("🔇 " if muted else "") + (title or "New tab"))
            self.tabbar.setTabToolTip(i, title)
            self._vtab_refresh_row(view)   # mirror the title into the left tab list
            if view is self.current_view():
                self._set_window_title(title)

    def _toggle_mute(self, view):
        if view is None:
            return
        p = view.page()
        p.setAudioMuted(not p.isAudioMuted())
        self._set_tab_text(view, view.title())

    def _set_window_title(self, title: str):
        prefix = f"[{self.engagement.name}] " if self.engagement else ""
        self._set_title(prefix + (f"{title} - {APP}" if title and title != "New tab" else APP))

    def _remove_tab(self, i):
        view = self.tabbar.tabData(i)
        self._failed.pop(view, None)
        self._loading_views.discard(view)
        self._theme_dirty_views.discard(view)
        self.tabbar.removeTab(i)
        self.stack.removeWidget(view)
        view.deleteLater()
        self._sync_vtabs()   # keep the left tab list (if shown) in step

    def close_tab(self, i: int):
        if i < 0:
            return
        view = self.tabbar.tabData(i)
        if view is not None and not self.ephemeral:  # remember it for Ctrl+Shift+T (never in Tor/private)
            u = view.url().toString()
            if u and not u.startswith("wyrm://"):
                self._closed_tabs.append({"url": u, "title": view.title() or u})
                del self._closed_tabs[:-25]
        if self.tabbar.count() <= 1:
            self.current_view().setUrl(QUrl(HOME))
            return
        self._remove_tab(i)

    def reopen_closed_tab(self):
        if self._closed_tabs:
            self.new_tab(QUrl(self._closed_tabs.pop()["url"]))

    def reopen_tab_at(self, i: int):
        """Reopen one recently-closed tab by its position in the History page (0 = most recently closed)."""
        if 0 <= i < len(self._closed_tabs):
            rec = self._closed_tabs.pop(len(self._closed_tabs) - 1 - i)  # newest is at the end of the list
            self.new_tab(QUrl(rec["url"]))
            for j in range(self.tabbar.count()):  # refresh any open History page so the item drops off
                view = self.tabbar.tabData(j)
                u = view.url()
                if u.scheme() == "wyrm" and u.host() == "history":
                    view.reload()

    # ---------------------------------------------------------------- tab right-click menu (like other browsers)
    def _tab_context_menu(self, pos):
        from PySide6.QtWidgets import QMenu
        i = self.tabbar.tabAt(pos)
        n = self.tabbar.count()
        m = QMenu(self)
        m.addAction("New tab", self._new_tab_focus)
        if i >= 0:
            view = self.tabbar.tabData(i)
            m.addAction("Reload tab", lambda _c=False, v=view: v.reload() if v is not None else None)
            m.addAction("Hard reload (bypass cache)", lambda _c=False, v=view: self._hard_reload_view(v))
            m.addAction("Duplicate tab", lambda _c=False, j=i: self.duplicate_tab(j))
            muted = view.page().isAudioMuted() if view is not None else False
            m.addAction("Unmute tab" if muted else "Mute tab", lambda _c=False, v=view: self._toggle_mute(v))
            m.addSeparator()
            # move the tab to another window (tear-off / merge), keeping its page and history
            m.addAction("Move tab to new window", lambda _c=False, j=i: self.move_tab_to_new_window(j))
            targets = self._merge_targets()
            if targets:
                sub = m.addMenu("Move tab to window")
                for w in targets:
                    title = (w.windowTitle() or "Wyrm")[:40]
                    sub.addAction(title, lambda _c=False, j=i, tw=w: self.move_tab_to_window(j, tw))
            m.addSeparator()
            m.addAction("Close tab", lambda _c=False, j=i: self.close_tab(j))
            a_other = m.addAction("Close other tabs", lambda _c=False, j=i: self.close_other_tabs(j))
            a_other.setEnabled(n > 1)
            a_right = m.addAction("Close tabs to the right", lambda _c=False, j=i: self.close_tabs_to_right(j))
            a_right.setEnabled(i < n - 1)
        m.addAction("Close all tabs", self.close_all_tabs)
        m.addSeparator()
        a_reopen = m.addAction("Reopen closed tab", self.reopen_closed_tab)
        a_reopen.setEnabled(bool(self._closed_tabs))
        m.exec(self.tabbar.mapToGlobal(pos))

    def duplicate_tab(self, i: int):
        view = self.tabbar.tabData(i) if i >= 0 else None
        if view is not None:
            self.new_tab(QUrl(view.url()))

    # ---------------------------------------------------------------- move tabs between windows (tear-off / merge)
    def _merge_targets(self) -> list:
        """Other open normal windows that share this window's profile, so a tab can move there with its live page."""
        from PySide6.QtWidgets import QApplication
        out = []
        for w in QApplication.instance().topLevelWidgets():
            if (w is not self and isinstance(w, type(self)) and not w.isHidden()
                    and getattr(w, "profile", None) is self.profile):
                out.append(w)
        return out

    def _detach_tab(self, i: int):
        """Remove the tab at `i` from this window WITHOUT destroying its view, and return the view (or None)."""
        view = self.tabbar.tabData(i) if 0 <= i < self.tabbar.count() else None
        if view is None:
            return None
        self._unwire_view(view)
        self._failed.pop(view, None)
        self._loading_views.discard(view)
        self._theme_dirty_views.discard(view)
        self.tabbar.removeTab(i)
        self.stack.removeWidget(view)    # reparents out of the stack; the view stays alive
        self._sync_vtabs()
        return view

    def _adopt_tab(self, view, title: str = ""):
        """Add an existing view (from another window) as a new tab in this window and make it current."""
        view.rebind(self)
        self.stack.addWidget(view)
        idx = self.tabbar.addTab(title or view.title() or "New tab")
        self.tabbar.setTabData(idx, view)
        self._wire_view(view)
        icon = view.icon()
        if not icon.isNull():
            self.tabbar.setTabIcon(idx, icon)
        self.tabbar.setCurrentIndex(idx)
        self.stack.setCurrentWidget(view)
        self._sync_vtabs()
        self._set_tab_text(view, view.title())

    def move_tab_to_window(self, i: int, target):
        if target is None or target is self or getattr(target, "profile", None) is not self.profile:
            return
        last = self.tabbar.count() <= 1
        title = self.tabbar.tabText(i)
        view = self._detach_tab(i)
        if view is None:
            return
        target._adopt_tab(view, title)
        target.raise_()
        target.activateWindow()
        if last:
            self.new_tab(QUrl(HOME))   # never leave this window with zero tabs
        self._sync_chrome()

    def move_tab_to_new_window(self, i: int):
        view = self.tabbar.tabData(i) if 0 <= i < self.tabbar.count() else None
        if view is None:
            return
        w = self.open_new_window()        # same process
        # make the new window share this one's engagement/profile so the live page can move into it
        w.engagement = self.engagement
        w.profile = self.profile
        # the fresh window starts with one placeholder HOME tab; move our tab in, then drop the placeholder
        placeholders = [w.tabbar.tabData(j) for j in range(w.tabbar.count())]
        self.move_tab_to_window(i, w)
        for j in range(w.tabbar.count() - 1, -1, -1):
            if w.tabbar.tabData(j) in placeholders:
                w.close_tab(j)

    def close_all_tabs(self):
        """Close every tab; the last one resets to Home so the window stays open (all are kept for Ctrl+Shift+T)."""
        for j in range(self.tabbar.count() - 1, -1, -1):   # high → low so indices stay valid
            self.close_tab(j)

    def close_other_tabs(self, i: int):
        for j in range(self.tabbar.count() - 1, -1, -1):   # high → low so indices stay valid; keep tab i
            if j != i:
                self.close_tab(j)

    def close_tabs_to_right(self, i: int):
        for j in range(self.tabbar.count() - 1, i, -1):
            self.close_tab(j)

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

    def _on_tab_changed(self, _i):
        v = self.current_view()
        if not v:
            return
        if v in self._theme_dirty_views:   # a theme/mode changed while this tab was in the background: refresh now
            self._theme_dirty_views.discard(v)
            if v.url().scheme() == "wyrm":
                from PySide6.QtWebEngineCore import QWebEnginePage
                v.page().triggerAction(QWebEnginePage.WebAction.ReloadAndBypassCache)
        self.stack.setCurrentWidget(v)
        self._vtab_update_current()   # highlight the active row in the left tab list
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
            # hide the http(s):// scheme like modern browsers — the lock/unlock icon already shows security.
            # Re-typing a bare host still resolves fine (engines.resolve adds the scheme back).
            self.urlbar.setText(u[8:] if u.startswith("https://") else u[7:] if u.startswith("http://") else u)
        self.urlbar.setCursorPosition(0)
        p = theme.PALETTES[self.theme_name]
        if getattr(v, "cert_error", False) and url.scheme() == "https":
            icon, tip = "unlock", "Certificate problem — the connection is NOT secure (click to inspect)"
        else:
            icon = {"https": "lock", "http": "unlock"}.get(url.scheme(), "search")
            tip = {"lock": "Secure connection (HTTPS) — click to view the certificate",
                   "unlock": "Not secure (plain HTTP)"}.get(icon, "")
        self.url_icon.setPixmap(make_icon(icon, p["error"] if icon == "unlock" else p["muted"]).pixmap(18, 18))
        self.url_icon.setToolTip(tip)
        h = v.history()
        self.b_back.setEnabled(h.canGoBack())
        self.b_fwd.setEnabled(h.canGoForward())
        self._update_scope_badge()
        if hasattr(self, "_refresh_bm_star"):   # URL-bar bookmark star reflects the new page (L-9)
            self._refresh_bm_star()
        self._ext_store_check(url)  # Chrome Web Store page: offer "Add to Wyrm Browser"

    # ================================================================ errors / offline
    def _sitemap_status(self, info):
        """QA-L5: remember the HTTP status of each page load so the Site map can tell 404s from real pages."""
        try:
            sm = self.security.sitemap
            sm.note_status(info.url().toString(), info.httpStatusCode())
        except Exception:  # noqa: BLE001 - older Qt without httpStatusCode, or panel not built yet
            pass

    def _sitemap_links(self, view):
        """QA-L5: hand the page's same-origin <a href> links to the Site map (read from the DOM, nothing fetched)."""
        url = view.url().toString()
        sm = getattr(getattr(self, "security", None), "sitemap", None)
        if sm is None or not url.startswith("http"):
            return
        from ..panels.sitemap import LINKS_JS
        view.page().runJavaScript(LINKS_JS, 1, lambda res, u=url: isinstance(res, list) and sm.note_links(u, res))

    def _on_loading_info(self, view, info):
        status = info.status()
        if status == QWebEngineLoadingInfo.LoadStatus.LoadStartedStatus:
            if not info.url().toString().startswith("data:"):
                self._failed.pop(view, None)
        elif status == QWebEngineLoadingInfo.LoadStatus.LoadSucceededStatus and not info.isErrorPage()                 and info.url().scheme() in ("http", "https"):
            try:  # the page's response headers, for Scanner -> Technologies on the open page
                # values are lists (a header can repeat, e.g. Set-Cookie): join them with newlines
                hdrs = {}
                for k, v in info.responseHeaders().items():
                    vals = v if isinstance(v, (list, tuple)) else [v]
                    hdrs[bytes(k).decode("latin-1")] = "\n".join(bytes(x).decode("latin-1") for x in vals)
                view.resp_headers = (info.url().toString(), hdrs)
            except Exception:  # noqa: BLE001
                view.resp_headers = (info.url().toString(), {})
            self._sitemap_status(info)
        elif status == QWebEngineLoadingInfo.LoadStatus.LoadFailedStatus:
            code = info.errorCode()
            D = QWebEngineLoadingInfo.ErrorDomain
            if info.errorDomain() == D.HttpStatusCodeDomain:
                self._sitemap_status(info)   # QA-L5: 404 / 500 pages show their status in the Site map
            if code == -3 or info.errorDomain() in (D.HttpStatusCodeDomain, D.NoErrorDomain):
                return  # user pressed stop, or the server sent its own error page: show it as-is
            url = info.url().toString()
            host = info.url().host()
            self._failed[view] = QUrl(url)
            if url in getattr(self, "_intercept_held", ()):  # waiting in the Intercept window
                self._intercept_held.discard(url)
                self._failed.pop(view, None)
                from ..panels.intercept import held_page
                view.setHtml(held_page(url), QUrl("data:text/html,intercept"))
                return
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
                # The start page was drawn without news while offline. Show the headlines we already
                # have right away: _news_ready only redraws when they change, and the next fetch
                # usually brings the same ones, so without this they stay hidden until you navigate.
                if self._news:
                    self._refresh_home_pages()
                QTimer.singleShot(1500, self._fetch_news)  # back online: get fresh headlines
        elif was and self._news:
            self._refresh_home_pages()  # offline: hide the news section

    def _retry_failed(self):
        for view, url in list(self._failed.items()):
            view.setUrl(url)

    def _on_load_finished(self, view, ok):
        if view.popup:
            view.popup = False
            self._check_popup(view)
        if ok:
            if self.history_db is not None and view.url().scheme() in ("http", "https"):
                self.history_db.record(view.url().toString(), view.title())
            self._apply_cosmetics(view)
            self._sitemap_links(view)
            QTimer.singleShot(4000, lambda v=view: self._index_of(v) >= 0 and self._apply_cosmetics(v))  # late content
        if view is self.current_view():
            self._update_shield_button()
            self._loading(view, False)
            self._sync_chrome()
            self._analyze_paper(view, count_visit=True)
            if view not in self._failed:
                self.security.overview.page_loaded(view)
