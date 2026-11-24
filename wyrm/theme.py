#------------------------------------------------------------------------------
# Wyrm — wyrm/theme.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Carbon-style themes (IBM Carbon Design System tokens): Gray 100 (dark) and White (light).

Carbon traits applied here: IBM Plex type, square corners, flat layers instead of borders/shadows,
bottom-border fields, 2px focus outlines, line tabs, and a dark UI-shell header in both themes.
"""
from __future__ import annotations

from pathlib import Path
from string import Template

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette
from PySide6.QtWidgets import QAbstractButton, QComboBox, QMenu, QMessageBox, QProxyStyle, QTabBar

FONT_DIR = Path(__file__).parent / "assets" / "fonts"
SANS = "IBM Plex Sans"
MONO = "IBM Plex Mono"

SHELL = dict(shell="#161616", shell_text="#f4f4f4", shell_muted="#c6c6c6", shell_hover="#2c2c2c",
             shell_active="#393939", shell_border="#393939")

PALETTES = {
    "dark": dict(SHELL, bg="#161616", layer="#262626", layer2="#393939", hover="#333333", selected="#393939",
                 field="#262626", text="#f4f4f4", muted="#c6c6c6", placeholder="#6f6f6f", border="#393939",
                 strong="#6f6f6f", interactive="#4589ff", button="#0f62fe", button_hover="#0353e9",
                 secondary="#6f6f6f", secondary_hover="#606060", link="#78a9ff", focus="#ffffff", icon="#f4f4f4",
                 error="#fa4d56", success="#42be65", warning="#f1c21b",
                 tag_ok_bg="#044317", tag_ok_fg="#6fdc8c", tag_bad_bg="#750e13", tag_bad_fg="#ffb3b8",
                 banner="#3d3100", banner_text="#f1c21b", banner_border="#8e6a00"),
    "light": dict(SHELL, bg="#ffffff", layer="#f4f4f4", layer2="#e0e0e0", hover="#e8e8e8", selected="#e0e0e0",
                  field="#f4f4f4", text="#161616", muted="#525252", placeholder="#a8a8a8", border="#e0e0e0",
                  strong="#8d8d8d", interactive="#0f62fe", button="#0f62fe", button_hover="#0353e9",
                  secondary="#393939", secondary_hover="#4c4c4c", link="#0f62fe", focus="#0f62fe", icon="#161616",
                  error="#da1e28", success="#24a148", warning="#f1c21b",
                  tag_ok_bg="#a7f0ba", tag_ok_fg="#0e6027", tag_bad_bg="#ffd7d9", tag_bad_fg="#a2191f",
                  banner="#fcf4d6", banner_text="#161616", banner_border="#f1c21b"),
    # Hacker: the dark "pro tool" look used by professional testing tools (graphite neutrals, orange accent, as in
    # Burp Suite's dark theme), with mono type in the address bar and data views (see HACKER_QSS).
    "hacker": dict(shell="#0b0d10", shell_text="#e6e8eb", shell_muted="#9aa3ad", shell_hover="#1a1e23",
                   shell_active="#23282e", shell_border="#2a3037",
                   bg="#111418", layer="#181c21", layer2="#21262c", hover="#1f242a", selected="#2a2f36",
                   field="#14181c", text="#e6e8eb", muted="#9aa3ad", placeholder="#5f6873", border="#2a3037",
                   strong="#4b545e", interactive="#ff7a1a", button="#e8620c", button_hover="#ff7a1a",
                   secondary="#2f353c", secondary_hover="#3a4149", link="#ffa45c", focus="#ff7a1a", icon="#d5d9de",
                   error="#ff5c5c", success="#3fb950", warning="#f0b429",
                   tag_ok_bg="#0f2e1a", tag_ok_fg="#7ee2a0", tag_bad_bg="#4a1414", tag_bad_fg="#ffb0b0",
                   banner="#2b1d0e", banner_text="#ffc078", banner_border="#e8620c"),
}

# Red/Blue team modes: Blue (default, defensive) keeps the blue accent; Red (offensive) swaps it to red.
MODE_ACCENT = {
    "blue": {"dark": {}, "light": {}},
    "red": {
        "dark": dict(interactive="#fa4d56", button="#da1e28", button_hover="#ba1b23", link="#ff8389", select="#da1e28"),
        "light": dict(interactive="#da1e28", button="#da1e28", button_hover="#ba1b23", link="#da1e28",
                      select="#da1e28", focus="#da1e28"),
        "hacker": dict(interactive="#ff4d4f", button="#d9363e", button_hover="#ff4d4f", link="#ff8a8c",
                       select="#ff4d4f", focus="#ff4d4f"),
    },
}


def resolve_palette(theme: str, mode: str = "blue") -> dict:
    p = dict(PALETTES[theme])
    p.update(MODE_ACCENT.get(mode, MODE_ACCENT["blue"]).get(theme, {}))
    return p


# Carbon status scale for findings / grades
SEVERITY = {"critical": "#da1e28", "high": "#ff832b", "medium": "#b28600", "low": "#4589ff", "info": "#8d8d8d"}
GRADE = {"A": "#24a148", "B": "#42be65", "C": "#f1c21b", "D": "#ff832b", "E": "#fa4d56", "F": "#da1e28"}

QSS = Template("""
* { font-family: "$sans"; }
QWidget { color: $text; font-size: 13px; }
QMainWindow, #Root { background: $bg; }
QMainWindow::separator { background: $border; width: 1px; height: 1px; }

/* ---------- UI shell header (always dark, like Carbon) ---------- */
QToolBar#ShellBar, QToolBar#NavToolBar { border: none; padding: 0; margin: 0; spacing: 0; }
QToolBar#ShellBar { background: $shell; }
QToolBar#NavToolBar { background: $layer; }
QTabBar#MainTabs::close-button { image: url("$close"); subcontrol-position: right; width: 16px; height: 16px; margin: 0 4px; }
QTabBar#MainTabs::close-button:hover { background: $shell_active; }
#TabStrip { background: $shell; border-bottom: 1px solid $shell_border; }
#Brand { padding: 0; }
#TorTag { background: #8a3ffc; color: #ffffff; font-size: 12px; padding: 1px 8px; }
#PrivateTag { background: #525252; color: #ffffff; font-size: 12px; font-weight: 600; padding: 1px 8px; }
#BrandDivider { background: $shell_border; }
#TabStrip QToolButton { border: none; border-radius: 0; padding: 0; background: transparent; min-width: 40px; min-height: 40px; }
#TabStrip QToolButton:hover { background: $shell_hover; }
#TabStrip QToolButton#CloseButton:hover { background: #c42b1c; }
#TabStrip QToolButton#CaptionButton, #TabStrip QToolButton#CloseButton { min-width: 46px; }
/* ---------- left tool rail (Arc/Vivaldi-style launcher) ---------- */
#ToolRail { background: $shell; border-right: 1px solid $shell_border; }
#ToolRail QToolButton { border: none; border-radius: 0; background: transparent; min-width: 40px; min-height: 40px; max-width: 40px; max-height: 40px; }
#ToolRail QToolButton:hover { background: $shell_hover; }
#Content { background: $bg; }
QTabBar#MainTabs { background: transparent; }
QTabBar#MainTabs::tab {
    background: transparent; color: $shell_muted; padding: 0 8px 0 16px; height: 38px; margin: 3px 2px 0 2px;
    border: none; border-radius: 0;
    min-width: 140px; max-width: 220px; font-size: 13px;
}
QTabBar#MainTabs::tab:hover:!selected { background: $shell_hover; color: $shell_text; }
QTabBar#MainTabs::tab:selected { background: $layer; color: $text; border-top: 3px solid $interactive; }
/* vertical tabs (left panel, Edge/Arc-style) */
#VTabs { background: $shell; border-right: 1px solid $shell_border; }
QTabBar#MainTabs[vertical="true"]::tab { min-width: 196px; max-width: 212px; height: 34px; padding: 0 10px; margin: 2px 4px; border-top: none; border-radius: 4px; }
QTabBar#MainTabs[vertical="true"]::tab:selected { background: $layer; color: $text; border-top: none; border-left: 3px solid $interactive; }

/* ---------- navigation bar (soft, rounded, pill address bar) ---------- */
#NavBar { background: $layer; border-bottom: 1px solid $border; }
/* fixed 40x40 squares, no margin: the hover/checked background is always a square with the icon dead-centre */
#NavBar QToolButton { border: none; border-radius: 0; padding: 0; background: transparent; min-width: 40px; min-height: 40px; max-width: 40px; max-height: 40px; margin: 0; }
#NavBar QToolButton:hover { background: $hover; }
/* "Update" pill, shown only when a newer release exists (like Brave's) */
#NavBar QPushButton#UpdateButton { background: $button; color: #ffffff; font-weight: 600; font-size: 13px;
    border: none; border-radius: 15px; padding: 0 14px 0 10px; min-height: 30px; max-height: 30px; margin: 0 6px; }
#NavBar QPushButton#UpdateButton:hover { background: $button_hover; }
#NavBar QLabel#Badge { background: $interactive; color: #ffffff; font-size: 10px; font-weight: 600;
    border-radius: 8px; padding: 0 4px; min-width: 8px; }
#NavBar QToolButton:checked { background: $selected; }
#NavBar QToolButton:focus { border: 2px solid $focus; }
QLineEdit#UrlBar {
    background: $field; border: 1px solid transparent; border-radius: 0; padding: 0 18px;
    min-height: 38px; font-size: 14px; color: $text; selection-background-color: $interactive;
}
QLineEdit#UrlBar:hover { background: $hover; }
QLineEdit#UrlBar:focus { background: $bg; border: 2px solid $interactive; padding: 0 17px; }
QComboBox#Engine, QComboBox#Engagement {
    background: $field; border: 1px solid transparent; border-radius: 0; padding: 0 14px;
    min-height: 36px; color: $text; font-size: 13px;
}
QComboBox#Engagement { font-weight: 600; }
QComboBox#Engine:hover, QComboBox#Engagement:hover { background: $hover; }
QComboBox#Engine:focus, QComboBox#Engagement:focus { border: 1px solid $focus; }
QLabel#ScopeBadge { border-radius: 12px; padding: 2px 10px; font-size: 12px; }
QLabel#UrlIcon { background: transparent; }
LoadingBar { background: $layer; }
#OfflineBanner { background: $banner; border-left: 3px solid $banner_border; }
#OfflineBanner QLabel { color: $banner_text; }
#DownloadsPopup { background: $bg; border: 1px solid $border; }
#DownloadsPopup QFrame#DlRow { background: $layer; border: 1px solid $border; }
#DownloadsPopup QLabel#DlName { font-weight: 600; color: $text; }
#DownloadsPopup QProgressBar { border: 1px solid $border; text-align: center; height: 16px; background: $field; }
#DownloadsPopup QProgressBar::chunk { background: $interactive; }
#InfoBanner { background: $banner; border-left: 3px solid $interactive; }
#InfoBanner QLabel { color: $banner_text; }

/* ---------- panels ---------- */
QDockWidget { color: $text; font-size: 14px; }
QScrollArea#PanelNav { background: $layer; border: none; border-right: 1px solid $border; }
QWidget#NavBody { background: $layer; }
QLabel#NavGroup { color: $strong; font-size: 10.5px; font-weight: 700; letter-spacing: 1px; background: transparent; }
QPushButton#NavItem { background: transparent; border: none; border-left: 3px solid transparent; border-radius: 0;
    text-align: left; padding: 8px 12px 8px 14px; color: $muted; font-weight: 400; }
QPushButton#NavItem:hover { background: $hover; color: $text; }
QPushButton#NavItem:checked { background: $hover; color: $text; border-left: 3px solid $interactive; font-weight: 600; }

/* address-bar suggestion / history dropdown */
QListView#UrlPopup { background: $layer; border: 1px solid $border; outline: none;
    padding: 5px; font-size: 13.5px; color: $text; }
QListView#UrlPopup::item { padding: 7px 10px; border: none; border-radius: 0; color: $text; }
QListView#UrlPopup::item:selected, QListView#UrlPopup::item:hover {
    background: $hover; color: $text; border-left: 3px solid $interactive; padding-left: 7px; }
/* when a panel is detached into its own window, frame it so it's clearly separate */
QDockWidget[detached="true"] { border: 2px solid $interactive; }
QDockWidget[detached="true"] > #DockTitle { border-bottom: 1px solid $border; }
#DockTitle { background: $bg; }
#DockTitleLabel { font-size: 14px; font-weight: 600; color: $text; }
#DockTitle QToolButton { background: transparent; border: none; border-radius: 0; }
#DockTitle QToolButton:hover { background: $hover; }
#DockTitle QToolButton#DockClose:hover { background: #da1e28; }
QDockWidget > QWidget, QDialog, QMessageBox { background: $bg; }
QTabWidget::pane { border: none; background: $bg; }
QTabWidget > QTabBar::tab {
    background: transparent; color: $muted; padding: 9px 11px; border: none; border-radius: 0;
    border-bottom: 2px solid $border; font-size: 12.5px;
}
QTabWidget > QTabBar::tab:selected { color: $text; font-weight: 600; border-bottom: 2px solid $interactive; }
QTabWidget > QTabBar::tab:hover:!selected { color: $text; border-bottom: 2px solid $strong; }
QTabWidget > QTabBar QToolButton {  /* overflow scroll arrows */
    background: $layer; border: none; border-bottom: 2px solid $border; margin: 0; width: 18px;
}
QTabWidget > QTabBar QToolButton:hover { background: $hover; }
QTabWidget > QTabBar QToolButton:disabled { color: $placeholder; }

/* ---------- form controls (rounded, soft) ---------- */
QLineEdit, QPlainTextEdit, QTextBrowser, QSpinBox, QComboBox {
    background: $field; border: 1px solid $border; border-radius: 0; padding: 7px 12px;
    color: $text; selection-background-color: $interactive; selection-color: #ffffff;
}
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus { border: 1px solid $focus; }
/* combobox-popup: 0 = plain drop-down list BELOW the box on every OS (macOS otherwise pops the list over
   the box, centred on the current item, covering the input) */
QComboBox { combobox-popup: 0; }
QMessageBox, QDialog#ClearDataDialog, QDialog#ConfirmDialog { border: 1px solid $border; }  /* frameless message boxes keep a visible edge */
QLabel#DialogTitle { font-size: 18px; font-weight: 600; color: $text; }
QLabel#DialogBody { font-size: 14px; color: $text; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox::down-arrow { image: url("$chevron"); width: 12px; height: 12px; }
QComboBox QAbstractItemView { background: $layer; border: 1px solid $border; border-radius: 0;
    selection-background-color: $hover; selection-color: $text; outline: none; padding: 4px; }
QComboBox QAbstractItemView::item { padding: 6px 10px; min-height: 20px; }
QComboBox QAbstractItemView::item:hover, QComboBox QAbstractItemView::item:selected { background: $hover; color: $text; }
/* dropdown list scrollbar: always drawn with a visible track so users can see there is more to scroll */
QComboBox QAbstractItemView QScrollBar:vertical { background: $field; width: 12px; margin: 0; border-left: 1px solid $border; }
QComboBox QAbstractItemView QScrollBar::handle:vertical { background: $strong; min-height: 28px; margin: 2px; }
QComboBox QAbstractItemView QScrollBar::handle:vertical:hover { background: $text; }
QPushButton {
    background: $secondary; color: #ffffff; border: none; border-radius: 0; padding: 9px 18px; min-height: 15px;
    text-align: center; font-weight: 500;
}
QPushButton:hover { background: $secondary_hover; }
QPushButton:focus { border: 2px solid $focus; padding: 7px 16px; }
QPushButton:disabled { background: $layer2; color: $placeholder; }
QPushButton#Primary { background: $button; color: #ffffff; font-weight: 600; }
QPushButton#Primary:hover { background: $button_hover; }
QPushButton#Primary:disabled { background: $layer2; color: $placeholder; }
#FindBar { background: $layer; border: 1px solid $border; }
#FindBar QLineEdit { background: transparent; color: $text; }
#FindBar QToolButton { background: transparent; border: none; color: $text; min-width: 24px; min-height: 24px; }
#FindBar QToolButton:hover { background: $hover; }
QPushButton#Danger { background: #da1e28; color: #ffffff; font-weight: 600; }
QPushButton#Danger:hover { background: #b81922; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 16px; height: 16px; border: 1.5px solid $strong; border-radius: 0; background: transparent; }
QCheckBox::indicator:checked { background: $interactive; border-color: $interactive; image: url("$check"); }
QCheckBox::indicator:focus { border: 2px solid $focus; }

/* ---------- data tables / lists (soft rounded surfaces) ---------- */
QTreeWidget, QTableView, QListWidget {
    background: $layer; alternate-background-color: $layer; border: 1px solid $border; border-radius: 0;
    selection-background-color: $selected; selection-color: $text; outline: none; padding: 4px;
}
QTreeWidget::item, QListWidget::item { padding: 6px 6px; border-radius: 0; }
QTableView::item { padding: 3px 4px; }
QTreeWidget::item:hover, QListWidget::item:hover, QTableView::item:hover { background: $hover; }
QTreeWidget::item:selected, QListWidget::item:selected, QTableView::item:selected { background: $selected; color: $text; }
QHeaderView { background: transparent; }
QHeaderView::section { background: transparent; color: $muted; border: none; padding: 8px; font-weight: 600; font-size: 12px; }

/* ---------- misc ---------- */
QLabel#LinkBubble { background: $layer; color: $text; border: 1px solid $border; border-radius: 0; padding: 5px 10px; font-size: 12px; }
QLabel#Muted { color: $muted; font-size: 12px; }
QLabel#PaneLabel { color: $muted; font-size: 11px; font-weight: 600; }
QPushButton#Segment { background: $layer2; color: $muted; border: none; border-radius: 0; padding: 3px 10px; font-size: 12px; }
QPushButton#Segment:hover { background: $hover; color: $text; }
QPushButton#Segment:checked { background: $interactive; color: #ffffff; }
QMenu { background: $layer; border: 1px solid $border; border-radius: 0; padding: 6px; }
QMenu::item { padding: 8px 18px; border-radius: 0; }
QMenu::item:selected { background: $hover; }
QMenu::separator { height: 1px; background: $border; margin: 6px 8px; }
QToolTip { background: $text; color: $bg; border: none; padding: 5px 9px; border-radius: 0; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 2px; }
QScrollBar::handle:vertical { background: $strong; min-height: 32px; border-radius: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 2px; }
QScrollBar::handle:horizontal { background: $strong; min-width: 32px; border-radius: 0; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; }
QScrollBar::add-page, QScrollBar::sub-page { background: none; }
QSplitter::handle { background: $border; height: 1px; }
QStatusBar { background: $layer; color: $text; border-top: 1px solid $border; }
""")


def load_fonts() -> bool:
    ok = True
    for f in FONT_DIR.glob("*.ttf"):
        ok &= QFontDatabase.addApplicationFont(str(f)) >= 0
    return ok


def app_font() -> QFont:
    f = QFont(SANS)
    f.setPixelSize(13)
    f.setHintingPreference(QFont.HintingPreference.PreferNoHinting)
    return f


def _write_svg(cache_dir: Path, name: str, body: str) -> str:
    cache_dir.mkdir(parents=True, exist_ok=True)
    p = cache_dir / name
    p.write_text(f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'>{body}</svg>", encoding="utf-8")
    return p.as_posix()


def stylesheet(theme: str, cache_dir: Path, mode: str = "blue") -> str:
    p = resolve_palette(theme, mode)
    check = _write_svg(cache_dir, f"check-{theme}.svg",
                       f"<path d='M3.5 8.2l3 3 6-6.4' fill='none' stroke='{p['bg']}' stroke-width='1.6'/>")
    chevron = _write_svg(cache_dir, f"chevron-{theme}.svg",
                         f"<path d='M3 6l5 5 5-5' fill='none' stroke='{p['text']}' stroke-width='1.4'/>")
    close = _write_svg(cache_dir, "close.svg",
                       "<path d='M4.5 4.5l7 7M11.5 4.5l-7 7' fill='none' stroke='#c6c6c6' stroke-width='1.3'/>")
    dclose = _write_svg(cache_dir, f"dclose-{theme}.svg",
                        f"<path d='M4 4l8 8M12 4l-8 8' fill='none' stroke='{p['text']}' stroke-width='1.5'/>")
    dfloat = _write_svg(cache_dir, f"dfloat-{theme}.svg",
                        f"<rect x='4' y='5' width='8' height='7' fill='none' stroke='{p['text']}' stroke-width='1.3'/>"
                        f"<path d='M6 5V3h7v7h-2' fill='none' stroke='{p['text']}' stroke-width='1.3'/>")
    qss = QSS.substitute(p, sans=SANS, check=check, chevron=chevron, close=close, dclose=dclose, dfloat=dfloat)
    if theme == "hacker":
        qss += HACKER_QSS.substitute(p, mono=MONO)
    return qss


# Extra rules for the Hacker theme: mono type where you read data, accent edges, flatter controls.
HACKER_QSS = Template("""
QLineEdit#UrlBar { font-family: "$mono"; letter-spacing: 0.2px; border: 1px solid $border; }
QLineEdit#UrlBar:focus { border: 1px solid $interactive; }
QPlainTextEdit, QTextBrowser, QTextEdit, QTreeView, QTreeWidget, QTableView, QListWidget { font-family: "$mono"; }
QTreeView::item:selected, QTableView::item:selected, QListWidget::item:selected {
    background: $selected; color: $interactive; }
QHeaderView::section { font-family: "$mono"; text-transform: uppercase; color: $muted; }
QPushButton#Primary { border: 1px solid $interactive; }
QPushButton:hover { border-color: $interactive; }
QToolTip { background: $layer; color: $text; border: 1px solid $interactive; font-family: "$mono"; }
QTabBar::tab:selected { border-top: 2px solid $interactive; }
QDockWidget::title { font-family: "$mono"; color: $interactive; }
""")


def palette(theme: str, mode: str = "blue") -> QPalette:
    p = resolve_palette(theme, mode)
    pal = QPalette()
    R = QPalette.ColorRole
    for role, key in ((R.Window, "bg"), (R.Base, "field"), (R.AlternateBase, "layer"), (R.Button, "layer"),
                      (R.WindowText, "text"), (R.Text, "text"), (R.ButtonText, "text"), (R.ToolTipBase, "text"),
                      (R.ToolTipText, "bg"), (R.Highlight, "interactive"), (R.PlaceholderText, "placeholder"),
                      (R.Link, "link")):
        pal.setColor(role, QColor(p[key]))
    pal.setColor(R.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.ColorGroup.Disabled, R.Text, QColor(p["placeholder"]))
    pal.setColor(QPalette.ColorGroup.Disabled, R.ButtonText, QColor(p["placeholder"]))
    return pal


class _MenuInWindow(QObject):
    """Installed on each QMenu only (not app-wide): when a menu or submenu opens, keep it inside the browser
    window instead of letting it spill over the desktop. Submenus flip to the left when there's no room."""

    def eventFilter(self, menu, ev):
        try:
            if ev.type() == QEvent.Type.Show and isinstance(menu, QMenu):
                self._clamp(menu)
        except Exception:  # noqa: BLE001 - never let an error escape into Qt
            pass
        return False

    @staticmethod
    def _clamp(menu):
        host = menu.parentWidget()
        while host is not None and host.windowType() == Qt.WindowType.Popup:
            host = host.parentWidget()
        if host is None:
            return
        win = host.window().frameGeometry()
        g = menu.geometry()
        x, y = g.x(), g.y()
        parent_menu = menu.parentWidget() if isinstance(menu.parentWidget(), QMenu) else None
        if g.right() > win.right():
            x = (parent_menu.geometry().left() - g.width() + 2) if parent_menu else win.right() - g.width()
        x = max(win.left(), min(x, win.right() - g.width()))
        if g.bottom() > win.bottom():
            y = win.bottom() - g.height()
        y = max(win.top(), y)
        if (x, y) != (g.x(), g.y()):
            menu.move(x, y)


class AppStyle(QProxyStyle):
    """Fusion everywhere (same look on every OS); every clickable control (buttons, checkboxes, tabs, dropdowns)
    gets the pointing-hand cursor, and dropdown lists a visible scrollbar. Done in polish(), which Qt calls once per widget; an app-wide event filter is NOT safe here
    (it runs for every QObject event, including QtQuick internals, and recursed until the app crashed)."""

    def __init__(self):
        super().__init__("Fusion")

    _menu_filter = None

    def polish(self, *args):
        res = super().polish(*args)
        w = args[0] if args else None
        if isinstance(w, (QAbstractButton, QTabBar)):  # buttons, tool buttons, checkboxes, radios, tabs
            w.setCursor(Qt.CursorShape.PointingHandCursor)
        if isinstance(w, QMessageBox) and not w.property("wyrm_frameless"):
            # message boxes have their own Cancel / Close buttons: no OS title bar with a second close button
            w.setProperty("wyrm_frameless", True)
            w.setWindowFlags(Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        if isinstance(w, QMenu):
            import shiboken6
            # one shared instance, kept alive on the class; recreated if Qt already destroyed it (app shutdown)
            if AppStyle._menu_filter is None or not shiboken6.isValid(AppStyle._menu_filter):
                AppStyle._menu_filter = _MenuInWindow()
            try:
                w.removeEventFilter(AppStyle._menu_filter)
                w.installEventFilter(AppStyle._menu_filter)
            except RuntimeError:  # the menu itself is being destroyed
                pass
        if isinstance(w, QComboBox):
            hand = Qt.CursorShape.PointingHandCursor
            w.setCursor(hand)
            w.view().viewport().setCursor(hand)
            w.view().verticalScrollBar().setCursor(hand)
            w.view().setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        return res

