#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/search.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Address bar, search engines (with logos), history and suggestions."""
from __future__ import annotations

from PySide6.QtCore import QUrl

from .. import engines, theme
from ..ui.common import make_icon


class SearchMixin:
    """Address bar, search engines (with logos), history and suggestions. (Mixed into MainWindow.)"""

    def default_engine(self) -> str:
        return self.engine_box.currentData() if hasattr(self, "engine_box") else engines.DEFAULT_ENGINE

    def _load_engine_icons(self):
        """Logo for every engine: our own icons for internal ones, cached site favicons for the rest."""
        from .. import favicons
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

    def navigate(self, text: str):
        self._record_history(text.strip())
        url = engines.resolve(text, self.default_engine())
        c = self.urlbar.completer()           # close the suggestion dropdown so it doesn't linger over the page
        if c is not None:
            c.popup().hide()
        self.current_view().setUrl(QUrl.fromUserInput(url) if "://" not in url else QUrl(url))
        self.current_view().setFocus()

    def _record_history(self, text: str):
        if self.ephemeral or not text or text.startswith("wyrm://"):
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
        from .. import suggest
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
