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
from PySide6.QtWidgets import QApplication, QTabBar

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

    def _window_under(self, global_pos, exclude):
        """Another Wyrm browser window under the cursor (for drag-to-merge), or None."""
        w = QApplication.widgetAt(global_pos)
        top = w.window() if w is not None else None
        if top is not None and top is not exclude and hasattr(top, "_adopt_tab"):
            return top
        return None

    def mouseReleaseEvent(self, e):
        idx, self._press_index = self._press_index, -1
        gp = e.globalPosition().toPoint()
        local = e.position().toPoint()
        super().mouseReleaseEvent(e)   # let Qt finish any in-strip reorder first
        if e.button() != Qt.MouseButton.LeftButton or idx < 0:
            return
        win = self.window()
        if not hasattr(win, "move_tab_to_new_window"):
            return
        # the reorder above may have shifted indices; act on the tab that was actually grabbed
        data = self.tabData(idx)
        real = next((i for i in range(self.count()) if self.tabData(i) is data), idx)
        target = self._window_under(gp, win)
        if target is not None:          # dropped onto another window → merge the tab into it
            win.move_tab_to_window(real, target)
        elif self.count() > 1 and self._torn_off(local):   # dropped clear of the strip → new window
            win.move_tab_to_new_window(real)
