#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/panel.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""The Security panel dock: grouped navigation over all tabs."""
from __future__ import annotations

from html import escape

from PySide6.QtCore import QEvent, Qt
from PySide6.QtWidgets import (QDockWidget, QHBoxLayout, QLabel, QLineEdit, QMenu, QPushButton, QScrollArea,
                               QSizePolicy, QStackedWidget, QVBoxLayout, QWidget)

from . import toolnav

from .dom import DomTab
from .scanner import ScannerTab
from .findings import FindingsTab
from .intruder import IntruderTab
from .overview import OverviewTab
from .recon import ReconTab
from .shields import ShieldsTab
from .sitemap import SiteMapTab
from .tools import ToolsTab
from .traffic import TrafficTab


class SecurityPanel(QDockWidget):
    """Grouped vertical navigation over a stacked content area. Built to scale to many tools: short groups that
    collapse, pinned favourites at the top, and a search box that also finds tools nested inside tabs (toolnav)."""

    def __init__(self, win):
        super().__init__("Security", win)
        self.setObjectName("SecurityPanel")
        self.setMinimumWidth(360)
        self.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetMovable
                         | QDockWidget.DockWidgetFeature.DockWidgetFloatable
                         | QDockWidget.DockWidgetFeature.DockWidgetClosable)
        self.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea | Qt.DockWidgetArea.RightDockWidgetArea)
        self.overview = OverviewTab(win)
        self.traffic = TrafficTab(win)
        self.sitemap = SiteMapTab(win)
        self.recon = ReconTab(win)
        self.tools_tab = ToolsTab(win)
        self.findings = FindingsTab(win)
        self.shields = ShieldsTab(win)
        self.intruder = IntruderTab(win)
        self.dom = DomTab(win)
        self.scanner = ScannerTab(win)
        from .oob import OobTab
        self.oob = OobTab(win)
        from .capture import CaptureTab
        self.capture = CaptureTab(win)
        from .proxy import ProxyTab
        self.proxy = ProxyTab(win)
        from .wsintercept import WsTab
        self.ws = WsTab(win)
        from .workflows import WorkflowsTab
        self.workflows = WorkflowsTab(win)
        from .sessionauth import SessionAuthTab
        self.sessionauth = SessionAuthTab(win)
        from .addons import AddonsTab
        self.addons_tab = AddonsTab(win)
        from .audit import AuditTab
        self.audit = AuditTab(win)
        tabs = {"Shields": self.shields, "Overview": self.overview, "Site map": self.sitemap, "Recon": self.recon,
                "Traffic": self.traffic, "Proxy": self.proxy, "WebSocket": self.ws, "API & WebSocket": self.capture,
                "Scanner": self.scanner, "Audit": self.audit, "DOM Analysis": self.dom, "OOB Interactions": self.oob,
                "Tools": self.tools_tab, "Intruder": self.intruder, "Workflows": self.workflows,
                "Session / auth": self.sessionauth, "Findings": self.findings, "Add-ons": self.addons_tab}
        self._groups = [(title, list(items)) for title, items in toolnav.GROUPS]
        self._settings = getattr(win, "settings", None)
        self._pinned: list[str] = self._load_list("panel/pinned")
        self._collapsed: set[str] = set(self._load_list("panel/collapsed"))
        self._addon_info: dict[str, str] = {}   # add-on tab name -> description (hover + search)
        root = QWidget()
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        # left column: a tool search box above the grouped nav. The nav is a real scroll area (independent of the
        # fixed header); avoids the QListWidget::item padding/selection quirks that clipped the section headings.
        col = QWidget(objectName="NavColumn")
        col.setFixedWidth(176)
        cv = QVBoxLayout(col)
        cv.setContentsMargins(0, 0, 0, 0)
        cv.setSpacing(0)
        self.nav_search = QLineEdit(objectName="NavSearch")
        self.nav_search.setPlaceholderText("Find a tool…")
        self.nav_search.setClearButtonEnabled(True)
        self.nav_search.setToolTip("Search every tool, including the ones inside Tools and Scanner "
                                   "(e.g. repeater, jwt, nuclei). Enter opens the first match, Esc clears.")
        self.nav_search.textChanged.connect(lambda _t: self._render_nav())
        self.nav_search.returnPressed.connect(self._open_first_result)
        self.nav_search.installEventFilter(self)
        sbox = QHBoxLayout()
        sbox.setContentsMargins(10, 12, 10, 4)   # in the layout, not QSS margin: that misplaces the clear button
        sbox.addWidget(self.nav_search)
        cv.addLayout(sbox)
        self.nav = QScrollArea(objectName="PanelNav")
        self.nav.setWidgetResizable(True)
        self.nav.setFrameShape(self.nav.Shape.NoFrame)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        cv.addWidget(self.nav, 1)
        self._navbody = navbody = QWidget(objectName="NavBody")
        nb = QVBoxLayout(navbody)
        nb.setContentsMargins(0, 6, 0, 12)
        nb.setSpacing(2)
        self._nb = nb
        self._captions: dict[str, QPushButton] = {}
        self._results: list[QPushButton] = []
        self._result_entries: list[dict] = []
        self._empty = QLabel("No tool matches.", navbody, objectName="Muted")
        self._empty.setContentsMargins(16, 12, 12, 4)
        self._empty.setWordWrap(True)
        self._empty.hide()
        self.stack = QStackedWidget()
        self._nav_buttons: dict[str, tuple] = {}   # name -> (button, content widget)
        self._pages: dict[str, QScrollArea] = {}   # name -> stack page, created lazily on first show
        for _title, items in self._groups:
            for name in items:
                self._make_nav_item(name, tabs[name])
        self.nav.setWidget(navbody)
        navbody.setMinimumWidth(0)
        # Pages are wrapped in a scroll area and added to the stack lazily (see _ensure_page): wrapping/adding
        # all 18 tabs up front, plus the responsive-layout scan, cost ~0.4s per window (slow tab tear-off /
        # Ctrl+N). Only the tab actually shown is realized; the rest build on first view.
        self._polished: set = set()
        self._render_nav()
        h.addWidget(col)
        h.addWidget(self.stack, 1)
        self.setWidget(root)
        self.show_tab("Shields")

    def current_page(self):
        """The visible tab widget (pages are wrapped in scroll areas)."""
        w = self.stack.currentWidget()
        return w.widget() if isinstance(w, QScrollArea) else w

    def _polish_page(self, name):
        """Make one tab's button rows wrap and its long labels word-wrap. Run lazily on first show so building a
        window doesn't scan all 18 tabs' widget trees up front."""
        if name in self._polished:
            return
        self._polished.add(name)
        page = self._pages.get(name)
        if page is None:
            return
        from ..widgets import make_rows_wrap
        make_rows_wrap(page)   # button / filter rows wrap instead of forcing pages wider than the panel
        for lab in page.findChildren(QLabel):   # long explanatory labels wrap with the panel width
            if not lab.wordWrap() and len(lab.text()) > 40:
                lab.setWordWrap(True)
        from PySide6.QtWidgets import QAbstractItemView, QAbstractScrollArea
        for view in page.findChildren(QAbstractItemView):   # smooth per-pixel wheel scrolling (not per-row jumps)
            view.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
            view.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        for sa in page.findChildren(QAbstractScrollArea):
            bar = sa.verticalScrollBar()
            if bar is not None:
                bar.setSingleStep(16)   # a gentler wheel step than the default big jumps

    def _select(self, name):
        btn = self._nav_buttons[name][0]
        folded = [t for t, names, f in toolnav.sections(self._groups, self._pinned, self._collapsed)
                  if f and name in names]
        if folded or self.nav_search.text():   # make sure the chosen tool is visible in the nav
            self._collapsed.difference_update(folded)
            if folded:
                self._save_list("panel/collapsed", sorted(self._collapsed))
            self.nav_search.blockSignals(True)
            self.nav_search.clear()
            self.nav_search.blockSignals(False)
            self._render_nav()
        btn.setChecked(True)
        page = self._ensure_page(name)      # build this tab's stack page the first time it's shown (lazy)
        self.stack.setCurrentWidget(page)
        self.nav.ensureWidgetVisible(btn)   # QA-U8: scroll the active nav item into view so it looks selected

    def show_tab(self, name):
        self.show()
        if name in self._nav_buttons:
            self._select(name)

    def add_addon_tab(self, name, widget, desc: str = ""):
        """Append an add-on-provided tab under the ADD-ONS group (called by the add-on loader at startup)."""
        if name in self._nav_buttons:   # avoid a duplicate label clobbering the nav mapping
            name = f"{name} ({len(self._nav_buttons)})"
        btn = self._make_nav_item(name, widget)
        lay = widget.layout()
        if lay is not None:
            lay.setContentsMargins(16, 14, 16, 12)
            lay.setSpacing(10)
        if desc:
            self._addon_info[name] = desc
            btn.setToolTip(f"<b>{escape(name)}</b><br>{escape(desc)}<br><i>Right-click to pin</i>")
        else:
            self._addon_info.setdefault(name, "")
        self._groups[-1][1].append(name)   # ADD-ONS is the last group
        self._render_nav()
        return name

    # ------------------------------------------------------------------ nav: items, groups, pins, search
    def _make_nav_item(self, name, widget):
        # parented to the nav body even while hidden (collapsed group), so auto-exclusive selection stays in one group
        btn = QPushButton(name.replace("&", "&&"), self._navbody, objectName="NavItem")  # QA-M4: '&' isn't a mnemonic
        btn.setCheckable(True)
        btn.setAutoExclusive(True)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._fit(btn)
        info = toolnav.TOOL_INFO.get(name, ("",))[0]
        btn.setToolTip(f"<b>{escape(name)}</b><br>{escape(info)}<br><i>Right-click to pin</i>")
        btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        btn.customContextMenuRequested.connect(lambda pos, n=name, b=btn: self._nav_menu(n, b.mapToGlobal(pos)))
        btn.clicked.connect(lambda _c=False, n=name: self._select(n))
        btn.hide()
        widget.setParent(None)                 # held off the stack until first shown (lazy realization)
        self._nav_buttons[name] = (btn, widget)
        return btn

    def _ensure_page(self, name):
        """Wrap this tab's widget in a scroll area and add it to the stack the first time it's shown, then run the
        one-off per-tab layout pass. Returns the stack page (QScrollArea)."""
        page = self._pages.get(name)
        if page is not None:
            return page
        widget = self._nav_buttons[name][1]
        page = QScrollArea()  # tall pages scroll instead of squashing; width follows the panel
        page.setWidgetResizable(True)
        page.setFrameShape(QScrollArea.Shape.NoFrame)
        page.setWidget(widget)
        lay = widget.layout()
        if lay is not None:                    # one consistent outer margin + row spacing for every panel page
            lay.setContentsMargins(16, 14, 16, 12)
            lay.setSpacing(10)
        self.stack.addWidget(page)
        self._pages[name] = page
        self._polish_page(name)
        return page

    @staticmethod
    def _fit(w):
        """Rows never widen the nav (a long label would scroll it sideways and push every row off the left edge);
        the full name is in the hover text."""
        w.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        return w

    def _caption(self, title):
        cap = self._captions.get(title)
        if cap is None:
            cap = self._fit(QPushButton(self._navbody, objectName="NavGroup"))
            cap.setCursor(Qt.CursorShape.PointingHandCursor)
            cap.setToolTip("Click to show or hide this group")
            cap.clicked.connect(lambda _c=False, t=title: self._toggle_group(t))
            self._captions[title] = cap
        return cap

    def _render_nav(self):
        """Lay the nav out from its state: search results while searching, otherwise the (pinned +) groups."""
        nb = self._nb
        while nb.count():
            w = nb.takeAt(0).widget()
            if w is not None:
                w.hide()
        for b in self._results:
            b.deleteLater()
        self._results, self._result_entries = [], []
        q = self.nav_search.text().strip()
        if q:
            self._result_entries = toolnav.search(self._search_entries(), q)
            for e in self._result_entries:
                text = e["label"] if not e["sub"] else f"{e['label']}  ·  {e['tab']}"
                b = self._fit(QPushButton(text.replace("&", "&&"), self._navbody, objectName="NavItem"))
                b.setCursor(Qt.CursorShape.PointingHandCursor)
                b.setToolTip(f"<b>{escape(text)}</b><br>{escape(e['desc'])}")
                b.clicked.connect(lambda _c=False, ent=e: self._open_entry(ent))
                self._results.append(b)
                nb.addWidget(b)
                b.show()
            if not self._result_entries:
                nb.addWidget(self._empty)
                self._empty.show()
        else:
            for title, names, folded in toolnav.sections(self._groups, self._pinned, self._collapsed):
                cap = self._caption(title)
                # escape & (a QPushButton treats it as a mnemonic, so "PROXY & TRAFFIC" showed as "PROXY_TRAFFIC");
                # the count is shown only when the group is collapsed
                text = ("▸  " if folded else "▾  ") + title + (f"  ({len(names)})" if folded else "")
                cap.setText(text.replace("&", "&&"))
                nb.addWidget(cap)
                cap.show()
                if not folded:
                    for n in names:
                        btn = self._nav_buttons[n][0]
                        nb.addWidget(btn)
                        btn.show()
        nb.addStretch(1)

    def _search_entries(self):
        entries = toolnav.base_entries(n for n in self._nav_buttons if n not in self._addon_info)
        for name, desc in self._addon_info.items():
            entries.append(toolnav.entry(name, name, "", desc, "add-on"))
        for t in getattr(self.scanner, "_pd_tools", None) or []:   # ProjectDiscovery tools installed here
            entries.append(toolnav.entry(t.name, "Scanner", "pd:" + t.key, t.desc, t.key + " projectdiscovery"))
        return entries

    def _open_entry(self, e):
        self._select(e["tab"])
        sub = e["sub"]
        if sub.startswith("pd:"):
            box = getattr(self.scanner, "pd_box", None)
            i = box.findData(sub[3:]) if box is not None else -1
            if i >= 0:
                box.setCurrentIndex(i)
                box.setFocus()
        elif sub and e["tab"] == "Tools":
            self.tools_tab._select_tool(sub)

    def _open_first_result(self):
        if self._result_entries:
            self._open_entry(self._result_entries[0])

    def eventFilter(self, obj, ev):
        if obj is self.nav_search and ev.type() == QEvent.Type.KeyPress and ev.key() == Qt.Key.Key_Escape:
            self.nav_search.clear()
            return True
        return super().eventFilter(obj, ev)

    def _toggle_group(self, title):
        self._collapsed ^= {title}
        self._save_list("panel/collapsed", sorted(self._collapsed))
        self._render_nav()

    def _nav_menu(self, name, gpos):
        m = QMenu(self)
        if name in self._pinned:
            m.addAction("Unpin", lambda: self.set_pinned(name, False))
        else:
            m.addAction("Pin to top", lambda: self.set_pinned(name, True))
        m.exec(gpos)

    def set_pinned(self, name, pinned: bool):
        if pinned and name not in self._pinned:
            self._pinned.append(name)
        elif not pinned and name in self._pinned:
            self._pinned.remove(name)
        self._save_list("panel/pinned", self._pinned)
        self._render_nav()

    def _load_list(self, key) -> list[str]:
        if self._settings is None:
            return []
        v = self._settings.value(key, [])
        if isinstance(v, str):   # QSettings hands back a bare string for a one-item list on some platforms
            v = [v] if v else []
        return [str(x) for x in (v or [])]

    def _save_list(self, key, items):
        if self._settings is not None:
            self._settings.setValue(key, list(items))

    def _fade(self, w):
        # Deliberately a no-op. A QGraphicsOpacityEffect fade used to run here, but it disabled native rendering
        # for web-view pages and swallowed the first click after switching tools ("had to click twice"). Switching
        # tabs is now instant and reliable.
        return
