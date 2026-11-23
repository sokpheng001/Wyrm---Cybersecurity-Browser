#------------------------------------------------------------------------------
# Wyrm — wyrm/panel.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Research side panel: current-paper card, papers linked on this page, and the saved library."""
from __future__ import annotations

from html import escape

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox, QDockWidget, QFileDialog, QHBoxLayout, QLabel, QLineEdit, QListWidget, QListWidgetItem,
    QPushButton, QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
)

from . import scholar

ROLE_URL = Qt.ItemDataRole.UserRole
ROLE_KEY = Qt.ItemDataRole.UserRole + 1


class ResearchPanel(QDockWidget):
    open_url = Signal(str)        # open in current tab
    save_toggled = Signal(str, bool)  # key, saved
    rescan = Signal()

    def __init__(self, library, parent=None):
        super().__init__("Research", parent)
        self.library = library
        self.meta: dict | None = None
        self.key: str | None = None
        self._page_papers: list[dict] = []
        self.setObjectName("ResearchPanel")
        self.setMinimumWidth(320)

        tabs = QTabWidget()
        tabs.addTab(self._build_page_tab(), "This page")
        tabs.addTab(self._build_library_tab(), "Library")
        tabs.currentChanged.connect(lambda i: i == 1 and self.refresh_library())
        self.setWidget(tabs)
        self.show_paper(None)

    # ------------------------------------------------------------ "This page"
    def _build_page_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.card = QTextBrowser()
        self.card.setOpenLinks(False)
        self.card.anchorClicked.connect(lambda u: self.open_url.emit(u.toString()))
        v.addWidget(self.card, 3)

        row = QHBoxLayout()
        self.btn_save = QPushButton("★ Save")
        self.btn_save.clicked.connect(self._toggle_save)
        self.btn_bib = QPushButton("Copy BibTeX")
        self.btn_bib.clicked.connect(self._copy_bibtex)
        self.btn_pdf = QPushButton("Open PDF")
        self.btn_pdf.clicked.connect(lambda: self.meta and self.meta.get("pdf") and self.open_url.emit(self.meta["pdf"]))
        for b in (self.btn_save, self.btn_bib, self.btn_pdf):
            row.addWidget(b)
        v.addLayout(row)

        head = QHBoxLayout()
        self.links_label = QLabel("Papers linked on this page")
        self.links_label.setWordWrap(True)
        head.addWidget(self.links_label, 1)
        self.only_new = QCheckBox("unread only")
        self.only_new.toggled.connect(self._render_page_papers)
        head.addWidget(self.only_new)
        btn_rescan = QPushButton("↻")
        btn_rescan.setToolTip("Rescan page for paper links")
        btn_rescan.setFixedWidth(32)
        btn_rescan.clicked.connect(self.rescan.emit)
        head.addWidget(btn_rescan)
        v.addLayout(head)

        self.page_list = QListWidget()
        self.page_list.itemDoubleClicked.connect(lambda it: self.open_url.emit(it.data(ROLE_URL)))
        self.page_list.setToolTip("Double-click to open")
        v.addWidget(self.page_list, 2)
        return w

    def show_loading(self, key: str):
        self.key, self.meta = key, None
        self.card.setHtml(f"<p style='color:gray'>Looking up <b>{escape(key)}</b>…</p>")
        self._update_buttons()

    def show_error(self, key: str, err: str):
        if key != self.key:
            return
        self.card.setHtml(
            f"<p><b>{escape(key)}</b></p><p style='color:#b3261e'>Couldn't fetch metadata: {escape(err)}</p>"
            "<p style='color:gray'>You can still save it; it's already in your reading history.</p>"
        )
        self._update_buttons()

    def show_paper(self, meta: dict | None, key: str | None = None):
        self.meta = meta
        self.key = key or (meta or {}).get("key")
        if not meta:
            self.card.setHtml(
                "<p style='color:gray'>Not a paper page.</p><p style='color:gray'>Open an arXiv, DOI or publisher "
                "link to see its summary, citation count and BibTeX here. Links to papers on any page are listed "
                "below, with the ones you have already read highlighted.</p>"
            )
            self._update_buttons()
            return
        authors = meta.get("authors") or []
        a = ", ".join(authors[:6]) + (f" + {len(authors) - 6} more" if len(authors) > 6 else "")
        facts = [str(x) for x in (meta.get("year"), meta.get("venue")) if x]
        if meta.get("citations") is not None:
            facts.append(f"{meta['citations']:,} citations")
        if meta.get("references") is not None:
            facts.append(f"{meta['references']} refs")
        html = f"<h3 style='margin:0'>{escape(meta.get('title', ''))}</h3>"
        html += f"<p style='color:gray;margin:4px 0'>{escape(a)}<br>{escape(' · '.join(facts))}</p>"
        if meta.get("tldr"):
            html += f"<p><b>TL;DR</b> {escape(meta['tldr'])}</p>"
        if meta.get("abstract"):
            html += f"<p style='font-size:small'>{escape(meta['abstract'])}</p>"
        links = []
        if meta.get("arxiv"):
            links.append(f"<a href='https://www.semanticscholar.org/arxiv/{escape(meta['arxiv'])}'>Semantic Scholar page</a>")
        if meta.get("title"):
            from .engines import ENGINES
            links.append(f"<a href='{escape(ENGINES['gs'].url(meta['title']), quote=True)}'>Google Scholar</a>")
        html += "<p>" + " · ".join(links) + "</p>"
        html += f"<p style='color:gray;font-size:small'>source: {escape(meta.get('source', ''))}</p>"
        self.card.setHtml(html)
        self._update_buttons()

    def _update_buttons(self):
        has = bool(self.key)
        saved = has and self.library.status(self.key) == "saved"
        self.btn_save.setEnabled(has)
        self.btn_save.setText("★ Saved" if saved else "☆ Save")
        self.btn_bib.setEnabled(bool(self.meta))
        self.btn_pdf.setEnabled(bool(self.meta and self.meta.get("pdf")))

    def _toggle_save(self):
        if not self.key:
            return
        saved = self.library.status(self.key) != "saved"
        self.library.set_saved(self.key, saved, self.meta)
        self._update_buttons()
        self.save_toggled.emit(self.key, saved)

    def _copy_bibtex(self):
        if self.meta:
            from PySide6.QtGui import QGuiApplication
            QGuiApplication.clipboard().setText(scholar.to_bibtex(self.meta))
            self.btn_bib.setText("Copied ✓")
            from PySide6.QtCore import QTimer
            QTimer.singleShot(1500, lambda: self.btn_bib.setText("Copy BibTeX"))

    def show_page_papers(self, papers: list[dict]):
        self._page_papers = papers or []
        self._render_page_papers()

    def _render_page_papers(self):
        status = self.library.status_map()
        self.page_list.clear()
        n_read = n_saved = 0
        for p in self._page_papers:
            st = status.get(p["key"])
            n_read += st == "read"
            n_saved += st == "saved"
            if self.only_new.isChecked() and st:
                continue
            rec = self.library.get(p["key"]) if st else None
            title = (rec or {}).get("title") or p.get("text") or p["key"]
            mark = {"saved": "★ ", "read": "✓ "}.get(st, "• ")
            it = QListWidgetItem(f"{mark}{title}")
            it.setToolTip(f"{p['key']}\n{p['href']}")
            it.setData(ROLE_URL, p["href"])
            it.setData(ROLE_KEY, p["key"])
            if st == "saved":
                it.setForeground(Qt.GlobalColor.darkGreen)
            elif st == "read":
                it.setForeground(Qt.GlobalColor.darkYellow)
            self.page_list.addItem(it)
        total = len(self._page_papers)
        self.links_label.setText(
            f"<b>{total}</b> papers linked here · <span style='color:#c77700'>{n_read} read</span> · "
            f"<span style='color:#0a7d4f'>{n_saved} saved</span> · {total - n_read - n_saved} new"
        )

    # ------------------------------------------------------------ "Library"
    def _build_library_tab(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        self.filter = QLineEdit()
        self.filter.setPlaceholderText("Filter saved papers…")
        self.filter.textChanged.connect(self.refresh_library)
        v.addWidget(self.filter)
        self.lib_list = QListWidget()
        self.lib_list.itemDoubleClicked.connect(lambda it: self.open_url.emit(it.data(ROLE_URL)))
        v.addWidget(self.lib_list, 1)
        row = QHBoxLayout()
        b_open = QPushButton("Open")
        b_open.clicked.connect(lambda: (it := self.lib_list.currentItem()) and self.open_url.emit(it.data(ROLE_URL)))
        b_rm = QPushButton("Unsave")
        b_rm.clicked.connect(self._unsave_selected)
        b_bib = QPushButton("Export .bib")
        b_bib.clicked.connect(self._export_bib)
        for b in (b_open, b_rm, b_bib):
            row.addWidget(b)
        v.addLayout(row)
        return w

    def refresh_library(self):
        f = self.filter.text().lower().strip()
        self.lib_list.clear()
        for r in self.library.saved():
            meta = r.get("meta") or {}
            title = meta.get("title") or r.get("title") or r["key"]
            line = f"{title}  ({meta.get('year') or '?'})"
            hay = (line + " " + " ".join(meta.get("authors") or []) + " " + r["key"]).lower()
            if f and f not in hay:
                continue
            it = QListWidgetItem(line)
            it.setToolTip(r["key"])
            it.setData(ROLE_URL, r.get("url") or meta.get("url") or "")
            it.setData(ROLE_KEY, r["key"])
            self.lib_list.addItem(it)

    def _unsave_selected(self):
        it = self.lib_list.currentItem()
        if it:
            key = it.data(ROLE_KEY)
            self.library.set_saved(key, False)
            self.refresh_library()
            self._update_buttons()
            self.save_toggled.emit(key, False)

    def _export_bib(self):
        entries = [scholar.to_bibtex(r["meta"]) for r in self.library.saved() if r.get("meta")]
        if not entries:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export BibTeX", "library.bib", "BibTeX (*.bib)")
        if path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("\n\n".join(entries) + "\n")
