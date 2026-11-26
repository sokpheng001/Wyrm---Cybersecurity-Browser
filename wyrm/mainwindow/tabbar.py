#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/tabbar.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Tab strip with Chrome-style drag tear-off.

Dragging a tab stays a normal reorder inside the strip (Qt handles it). Dragging it well clear of the strip
(far below/above it) and releasing there pops that tab out into its own window, like other browsers."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QTabBar

_TEAR_MARGIN = 60   # px past the strip edge before a drag counts as "tear this tab off into a new window"


class TearOffTabBar(QTabBar):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._press_index = -1

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self._press_index = self.tabAt(e.position().toPoint())
        super().mousePressEvent(e)

    def _torn_off(self, pos) -> bool:
        # true when the pointer is dragged clear of the strip (so it's a tear-off, not an in-strip reorder)
        return pos.y() < -_TEAR_MARGIN or pos.y() > self.height() + _TEAR_MARGIN

    def mouseReleaseEvent(self, e):
        idx, self._press_index = self._press_index, -1
        super().mouseReleaseEvent(e)   # let Qt finish any in-strip reorder first
        if (e.button() == Qt.MouseButton.LeftButton and idx >= 0 and self.count() > 1
                and self._torn_off(e.position().toPoint())):
            win = self.window()
            if hasattr(win, "move_tab_to_new_window"):
                # the reorder above may have changed indices; move the tab that was actually grabbed
                data = self.tabData(idx)
                real = next((i for i in range(self.count()) if self.tabData(i) is data), idx)
                win.move_tab_to_new_window(real)
