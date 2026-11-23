#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/papers.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Research papers: metadata, link scanning and the Papers panel."""
from __future__ import annotations

import json

from PySide6.QtWebEngineCore import QWebEngineScript

from .. import scholar
from ..browser.scripts import CITESEE_JS


class PapersMixin:
    """Research papers: metadata, link scanning and the Papers panel. (Mixed into MainWindow.)"""

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
