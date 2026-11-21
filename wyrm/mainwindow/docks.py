#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/docks.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Side panels (docks): title bars, floating/detaching, developer tools."""
from __future__ import annotations

import sys

from PySide6.QtCore import QTimer, Qt
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWebEngineWidgets import QWebEngineView
from PySide6.QtWidgets import QHBoxLayout, QLabel, QToolButton, QWidget

from .. import theme
from ..ui.common import make_icon


class DocksMixin:
    """Side panels (docks): title bars, floating/detaching, developer tools. (Mixed into MainWindow.)"""

    def _dock_titlebar(self, dock, title: str):
        """Custom, clearly-visible title bar for a dock (float + close), replacing Qt's tiny native buttons."""
        bar = QWidget(objectName="DockTitle")
        h = QHBoxLayout(bar)
        # 6px top/bottom around the 30px buttons = 42px *natural* height. The dock lays its content out from the
        # title widget's sizeHint, so a fixed height alone made the content slide 12px under the title bar
        # (it clipped the top of Developer Tools).
        h.setContentsMargins(14, 6, 6, 6)
        h.setSpacing(2)
        lbl = QLabel(title, objectName="DockTitleLabel")
        h.addWidget(lbl, 1)
        b_float = QToolButton()
        b_float.setToolTip("Detach into its own window / dock back")
        b_float.clicked.connect(lambda: self._toggle_float(dock))
        b_close = QToolButton(objectName="DockClose")
        b_close.setToolTip("Close panel")
        b_close.clicked.connect(dock.close)
        for b, icon in ((b_float, "win_restore"), (b_close, "win_close")):
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setFixedSize(30, 30)
            b.setIconSize(b.iconSize().scaled(18, 18, Qt.AspectRatioMode.KeepAspectRatio))
            self._icon_buttons.append((b, icon))  # recolored by apply_theme
            h.addWidget(b)
        # close X turns white on the red hover (otherwise a dark X on red is hard to read)
        b_close.enterEvent = lambda e, b=b_close: b.setIcon(make_icon("win_close", "#ffffff"))
        b_close.leaveEvent = lambda e, b=b_close: b.setIcon(
            make_icon("win_close", theme.PALETTES[self.theme_name]["icon"]))
        bar.setFixedHeight(42)
        dock.setTitleBarWidget(bar)
        # frame the panel whenever it becomes a separate window (button OR dragged out), so the split is obvious
        dock.topLevelChanged.connect(lambda top, d=dock: self._mark_detached(d, top))

    def _mark_detached(self, dock, floating):
        dock.setProperty("detached", bool(floating))
        dock.style().unpolish(dock)
        dock.style().polish(dock)
        if floating:  # give the detached window a soft drop shadow so it reads as a separate window
            QTimer.singleShot(0, lambda: self._native_window_shadow(dock))

    @staticmethod
    def _native_window_shadow(w):
        """Best-effort native drop shadow for a floating window (Windows DWM). No-op elsewhere."""
        if sys.platform != "win32":
            return
        try:
            import ctypes

            class _MARGINS(ctypes.Structure):
                _fields_ = [("l", ctypes.c_int), ("r", ctypes.c_int), ("t", ctypes.c_int), ("b", ctypes.c_int)]
            hwnd = int(w.winId())
            # a 1px extended frame makes DWM composite a drop shadow around the window
            ctypes.windll.dwmapi.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(_MARGINS(1, 1, 1, 1)))
        except Exception:  # noqa: BLE001 - purely cosmetic
            pass

    def _toggle_float(self, dock):
        floating = not dock.isFloating()
        dock.setFloating(floating)
        if floating:  # give the detached window a comfortable size and center it on the main window
            dock.resize(760, max(640, int(self.height() * 0.8)))
            c = self.geometry().center()
            dock.move(c.x() - dock.width() // 2, c.y() - dock.height() // 2)
            dock.raise_()
            dock.activateWindow()
        self._mark_detached(dock, floating)

    def _setup_dock_titlebars(self):
        self._dock_titlebar(self.security, "Security")
        self._dock_titlebar(self.panel, "Papers")

    def _ensure_devtools(self):
        if getattr(self, "devtools_dock", None):
            return
        from PySide6.QtWidgets import QDockWidget
        self.devtools_view = QWebEngineView()
        self.devtools_view.setPage(QWebEnginePage(self.profile, self.devtools_view))
        self.devtools_dock = QDockWidget("Developer Tools", self)
        self.devtools_dock.setObjectName("DevToolsDock")
        self.devtools_dock.setWidget(self.devtools_view)
        self._dock_titlebar(self.devtools_dock, "Developer Tools")
        self.apply_theme(self.theme_mode)  # recolor the new title-bar icons
        self.addDockWidget(Qt.DockWidgetArea.BottomDockWidgetArea, self.devtools_dock)
        self.resizeDocks([self.devtools_dock], [340], Qt.Orientation.Vertical)

    def _devtools(self):
        v = self.current_view()
        if v:
            self.inspect(v, element=False)

    def inspect(self, view=None, element=True):
        view = view or self.current_view()
        if not view:
            return
        self._ensure_devtools()
        self.devtools_dock.show()
        view.page().setDevToolsPage(self.devtools_view.page())
        if element:
            view.page().triggerAction(QWebEnginePage.WebAction.InspectElement)
