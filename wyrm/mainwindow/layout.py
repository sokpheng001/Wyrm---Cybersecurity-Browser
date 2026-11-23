#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/layout.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Responsive layout: compact toolbar dropdowns and a side panel that follows the window."""
from __future__ import annotations

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import QComboBox, QSizePolicy


class LayoutMixin:
    """Responsive layout: compact toolbar dropdowns and a side panel that follows the window. (Mixed into MainWindow.)"""

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
