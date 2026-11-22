#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/panel.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""The Security panel dock: grouped navigation over all tabs."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QDockWidget, QHBoxLayout, QLabel, QPushButton, QScrollArea, QStackedWidget, QVBoxLayout, QWidget

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
    """Grouped vertical navigation (Protection / Website Intelligence / Traffic / Testing / Findings)
    over a stacked content area — reuses every existing tab widget, no horizontal tab overflow."""

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
        groups = [
            ("PROTECTION", [("Shields", self.shields)]),
            ("INTELLIGENCE", [("Overview", self.overview), ("Site map", self.sitemap), ("Recon", self.recon)]),
            ("TRAFFIC", [("Traffic", self.traffic)]),
            ("TESTING", [("Scanner", self.scanner), ("Intruder", self.intruder), ("DOM Analysis", self.dom),
                         ("Tools", self.tools_tab), ("OOB Interactions", self.oob)]),
            ("FINDINGS", [("Findings", self.findings)]),
        ]
        root = QWidget()
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        # left nav: section captions + nav buttons in a real scroll area (independent of the fixed header);
        # avoids the QListWidget::item padding/selection quirks that clipped the section headings.
        self.nav = QScrollArea(objectName="PanelNav")
        self.nav.setWidgetResizable(True)
        self.nav.setFixedWidth(150)
        self.nav.setFrameShape(self.nav.Shape.NoFrame)
        self.nav.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        navbody = QWidget(objectName="NavBody")
        nb = QVBoxLayout(navbody)
        nb.setContentsMargins(0, 18, 0, 12)  # breathing room between the fixed header and the first caption
        nb.setSpacing(2)
        self.stack = QStackedWidget()
        self._nav_buttons: dict[str, tuple] = {}   # name -> (button, stack index)
        for gi, (title, items) in enumerate(groups):
            cap = QLabel(title, objectName="NavGroup")
            cap.setContentsMargins(16, 16 if gi else 10, 12, 4)  # space above each group (header gap handled by NavBody margin)
            nb.addWidget(cap)
            for name, widget in items:
                btn = QPushButton(name, objectName="NavItem")
                btn.setCheckable(True)
                btn.setAutoExclusive(True)
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                page = QScrollArea()  # tall pages scroll instead of squashing; width follows the panel
                page.setWidgetResizable(True)
                page.setFrameShape(QScrollArea.Shape.NoFrame)
                page.setWidget(widget)
                idx = self.stack.addWidget(page)
                btn.clicked.connect(lambda _c=False, n=name: self._select(n))
                self._nav_buttons[name] = (btn, idx)
                nb.addWidget(btn)
        nb.addStretch(1)
        self.nav.setWidget(navbody)
        # one consistent outer margin + row spacing for every panel page (alignment & rhythm across tabs)
        for _n, (_b, idx) in self._nav_buttons.items():
            lay = self.stack.widget(idx).widget().layout()
            if lay is not None:
                lay.setContentsMargins(16, 14, 16, 12)
                lay.setSpacing(10)
        from ..widgets import make_rows_wrap
        make_rows_wrap(self.stack)  # button / filter rows wrap instead of forcing pages wider than the panel
        for lab in self.stack.findChildren(QLabel):  # long explanatory labels wrap with the panel width
            if not lab.wordWrap() and len(lab.text()) > 40:
                lab.setWordWrap(True)
        h.addWidget(self.nav)
        h.addWidget(self.stack, 1)
        self.setWidget(root)
        self.show_tab("Shields")

    def current_page(self):
        """The visible tab widget (pages are wrapped in scroll areas)."""
        w = self.stack.currentWidget()
        return w.widget() if isinstance(w, QScrollArea) else w

    def _select(self, name):
        btn, idx = self._nav_buttons[name]
        btn.setChecked(True)
        self.stack.setCurrentIndex(idx)

    def show_tab(self, name):
        self.show()
        if name in self._nav_buttons:
            self._select(name)

    def _fade(self, w):
        # Deliberately a no-op. A QGraphicsOpacityEffect fade used to run here, but it disabled native rendering
        # for web-view pages and swallowed the first click after switching tools ("had to click twice"). Switching
        # tabs is now instant and reliable.
        return
