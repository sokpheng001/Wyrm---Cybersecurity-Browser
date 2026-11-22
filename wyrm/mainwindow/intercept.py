#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/intercept.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Intercept on/off and the hand-off from the request interceptor to the Intercept window. (Mixed into MainWindow.)"""
from __future__ import annotations


class InterceptMixin:
    intercept_on = False

    def _intercept_state(self):
        if not hasattr(self, "_intercept_pass"):
            self._intercept_pass: set[str] = set()   # URLs forwarded from Intercept: let through once
            self._intercept_held: set[str] = set()   # URLs currently held (their tab shows "held")
            self._intercept_win = None

    def _intercept_window(self):
        self._intercept_state()
        if self._intercept_win is None:
            from ..panels.intercept import InterceptWindow
            self._intercept_win = InterceptWindow(self)
        return self._intercept_win

    def open_intercept(self):
        """Show the Intercept window and switch Intercept on."""
        w = self._intercept_window()
        self.set_intercept(True)
        w.toggle.setChecked(True)
        w.show()
        w.raise_()
        w.activateWindow()

    def set_intercept(self, on: bool):
        self._intercept_state()
        if self.intercept_on == bool(on):
            return
        self.intercept_on = bool(on)
        self.toast("Intercept ON: page requests are held for you to edit" if on else "Intercept OFF", 4000)
        b = getattr(self, "b_int", None)
        if b is not None:  # toolbar button shows the state
            from .. import theme
            p = theme.resolve_palette(self.theme_name, self.mode)
            b.setStyleSheet(f"QToolButton#InterceptButton {{ background: {p['interactive']}; border-radius: 4px; }}"
                            if on else "")
            b.setToolTip("Intercept is ON: page requests are held (click to open)" if on else
                         "Intercept requests: hold, edit, forward or drop (Ctrl+Alt+I)")

    def intercept_hold(self, view, req: dict):
        """Called (on the UI thread, after the interceptor returned) for each held page request."""
        w = self._intercept_window()
        self._intercept_held.add(req["url"])
        w.hold(view, req)
