#------------------------------------------------------------------------------
# Wyrm — wyrm/winframe.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Chrome-style window on Windows: tabs drawn in the title bar, native frame behaviour kept.

The system caption is removed (WM_NCCALCSIZE), but WS_THICKFRAME/WS_CAPTION stay on the window, so Windows
still provides snapping, Aero Shake, resize borders, min/max animations, rounded corners and the shadow.
WM_NCHITTEST tells Windows which pixels are resize edges and which are draggable caption (the empty tab strip).
Other platforms keep their native title bar.
"""
from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from PySide6.QtGui import QCursor

IS_WINDOWS = sys.platform == "win32"

WM_NCCALCSIZE, WM_NCHITTEST = 0x0083, 0x0084
HTCAPTION, HTLEFT, HTRIGHT, HTTOP, HTTOPLEFT, HTTOPRIGHT, HTBOTTOM, HTBOTTOMLEFT, HTBOTTOMRIGHT = 2, 10, 11, 12, 13, 14, 15, 16, 17
GWL_STYLE = -16
WS_CAPTION, WS_THICKFRAME, WS_SYSMENU, WS_MINIMIZEBOX, WS_MAXIMIZEBOX = 0x00C00000, 0x00040000, 0x00080000, 0x00020000, 0x00010000
SWP_FLAGS = 0x0001 | 0x0002 | 0x0004 | 0x0010 | 0x0020  # NOSIZE|NOMOVE|NOZORDER|NOACTIVATE|FRAMECHANGED
SM_CXSIZEFRAME, SM_CXPADDEDBORDER = 32, 92
DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_ROUND, DWMWA_BORDER_COLOR = 33, 2, 34


class MARGINS(ctypes.Structure):
    _fields_ = [("l", ctypes.c_int), ("r", ctypes.c_int), ("t", ctypes.c_int), ("b", ctypes.c_int)]


class NCCALCSIZE_PARAMS(ctypes.Structure):
    _fields_ = [("rgrc", wintypes.RECT * 3), ("lppos", ctypes.c_void_p)]


def install(win, border_color: str = "#161616"):
    """Call after the window's native handle exists (e.g. after show() or winId())."""
    if not IS_WINDOWS:
        return
    hwnd = int(win.winId())
    user32, dwm = ctypes.windll.user32, ctypes.windll.dwmapi
    get_style = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
    set_style = getattr(user32, "SetWindowLongPtrW", user32.SetWindowLongW)
    get_style.restype = ctypes.c_ssize_t
    style = get_style(hwnd, GWL_STYLE)
    set_style(hwnd, GWL_STYLE, ctypes.c_ssize_t(style | WS_CAPTION | WS_THICKFRAME | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX))
    dwm.DwmExtendFrameIntoClientArea(hwnd, ctypes.byref(MARGINS(0, 0, 0, 1)))  # keeps the DWM shadow
    pref = ctypes.c_int(DWMWCP_ROUND)
    dwm.DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, ctypes.byref(pref), 4)  # Win11 rounded corners
    set_border_color(win, border_color)
    user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, SWP_FLAGS)


def set_border_color(win, color: str):
    if not IS_WINDOWS:
        return
    c = color.lstrip("#")
    colorref = ctypes.c_uint(int(c[4:6] + c[2:4] + c[0:2], 16))  # 0x00BBGGRR
    ctypes.windll.dwmapi.DwmSetWindowAttribute(int(win.winId()), DWMWA_BORDER_COLOR, ctypes.byref(colorref), 4)


def native_event(win, event_type, message, is_caption) -> tuple[bool, int] | None:
    """Handle the two messages that make the custom title bar work. Returns None to fall through to Qt."""
    if not IS_WINDOWS or event_type.data() != b"windows_generic_MSG":
        return None
    msg = wintypes.MSG.from_address(int(message))
    if msg.message == WM_NCCALCSIZE and msg.wParam:
        if win.isMaximized():
            # a maximized window overhangs the screen by the frame thickness; pull the client rect back in
            user32 = ctypes.windll.user32
            dpi = user32.GetDpiForWindow(msg.hWnd)
            pad = user32.GetSystemMetricsForDpi(SM_CXSIZEFRAME, dpi) + user32.GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi)
            params = NCCALCSIZE_PARAMS.from_address(msg.lParam)
            r = params.rgrc[0]
            r.left += pad
            r.top += pad
            r.right -= pad
            r.bottom -= pad
        return True, 0  # whole window is client area: no system caption
    if msg.message == WM_NCHITTEST:
        gp = QCursor.pos()
        p = win.mapFromGlobal(gp)
        w, h = win.width(), win.height()
        if not win.isMaximized() and not win.isFullScreen():
            b = 6
            left, right, top, bottom = p.x() < b, p.x() >= w - b, p.y() < b, p.y() >= h - b
            if top and left:
                return True, HTTOPLEFT
            if top and right:
                return True, HTTOPRIGHT
            if bottom and left:
                return True, HTBOTTOMLEFT
            if bottom and right:
                return True, HTBOTTOMRIGHT
            if left:
                return True, HTLEFT
            if right:
                return True, HTRIGHT
            if top:
                return True, HTTOP
            if bottom:
                return True, HTBOTTOM
        if is_caption(gp):
            return True, HTCAPTION  # Windows handles drag, double-click maximize, snap, system menu
    return None
