"""Carbon-style themes (IBM Carbon Design System tokens): Gray 100 (dark) and White (light).

Carbon traits applied here: IBM Plex type, square corners, flat layers instead of borders/shadows,
bottom-border fields, 2px focus outlines, line tabs, and a dark UI-shell header in both themes.
"""
from __future__ import annotations

from pathlib import Path
from string import Template

from PySide6.QtGui import QColor, QFont, QFontDatabase, QPalette

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
}

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
#BrandDivider { background: $shell_border; }
#TabStrip QToolButton { border: none; border-radius: 0; padding: 0; background: transparent; min-width: 40px; min-height: 40px; }
#TabStrip QToolButton:hover { background: $shell_hover; }
#TabStrip QToolButton#CloseButton:hover { background: #c42b1c; }
#TabStrip QToolButton#CaptionButton, #TabStrip QToolButton#CloseButton { min-width: 46px; }
QTabBar#MainTabs { background: transparent; }
QTabBar#MainTabs::tab {
    background: transparent; color: $shell_muted; padding: 0 8px 0 16px; height: 40px; margin: 0;
    border: none; border-top: 2px solid transparent; border-radius: 0; min-width: 140px; max-width: 220px; font-size: 13px;
}
QTabBar#MainTabs::tab:hover:!selected { background: $shell_hover; color: $shell_text; }
QTabBar#MainTabs::tab:selected { background: $layer; color: $text; border-top: 2px solid $button; }

/* ---------- navigation bar ---------- */
#NavBar { background: $layer; border-bottom: 1px solid $border; }
#NavBar QToolButton { border: none; border-radius: 0; padding: 0; background: transparent; min-width: 40px; min-height: 40px; }
#NavBar QToolButton:hover { background: $hover; }
#NavBar QToolButton:checked { background: $selected; border-bottom: 2px solid $interactive; }
#NavBar QToolButton:focus { border: 2px solid $focus; }
QLineEdit#UrlBar {
    background: $bg; border: none; border-bottom: 1px solid $strong; border-radius: 0; padding: 0 16px;
    min-height: 38px; font-size: 14px; color: $text; selection-background-color: $interactive;
}
QLineEdit#UrlBar:hover { background: $hover; }
QLineEdit#UrlBar:focus { border: 2px solid $focus; padding: 0 15px; }
QComboBox#Engine, QComboBox#Engagement {
    background: $bg; border: none; border-bottom: 1px solid $strong; border-radius: 0; padding: 0 12px;
    min-height: 38px; color: $text; font-size: 13px;
}
QComboBox#Engagement { font-weight: 600; }
QComboBox#Engine:hover, QComboBox#Engagement:hover { background: $hover; }
QComboBox#Engine:focus, QComboBox#Engagement:focus { border: 2px solid $focus; }
QLabel#ScopeBadge { border-radius: 12px; padding: 2px 10px; font-size: 12px; }
QLabel#UrlIcon { background: transparent; }
LoadingBar { background: $layer; }
#OfflineBanner { background: $banner; border-left: 3px solid $banner_border; }
#OfflineBanner QLabel { color: $banner_text; }

/* ---------- panels ---------- */
QDockWidget { color: $text; font-size: 14px;
    titlebar-close-icon: url("$dclose"); titlebar-normal-icon: url("$dfloat"); }
QDockWidget::title { background: $bg; padding: 11px 44px 11px 16px; border-bottom: 1px solid $border; text-align: left; }
QDockWidget::close-button, QDockWidget::float-button {
    background: transparent; border: none; border-radius: 0; icon-size: 14px; width: 28px; height: 28px; padding: 0;
    subcontrol-position: center right;
}
QDockWidget::close-button { right: 8px; }
QDockWidget::float-button { right: 40px; }
QDockWidget::close-button:hover { background: #da1e28; }
QDockWidget::float-button:hover { background: $hover; }
QDockWidget > QWidget, QDialog, QMessageBox { background: $bg; }
QTabWidget::pane { border: none; background: $bg; }
QTabWidget > QTabBar::tab {
    background: transparent; color: $muted; padding: 10px 16px; border: none; border-radius: 0;
    border-bottom: 2px solid $border; font-size: 13px;
}
QTabWidget > QTabBar::tab:selected { color: $text; font-weight: 600; border-bottom: 2px solid $interactive; }
QTabWidget > QTabBar::tab:hover:!selected { color: $text; border-bottom: 2px solid $strong; }

/* ---------- form controls ---------- */
QLineEdit, QPlainTextEdit, QTextBrowser, QSpinBox, QComboBox {
    background: $field; border: none; border-bottom: 1px solid $strong; border-radius: 0; padding: 7px 12px;
    color: $text; selection-background-color: $interactive; selection-color: #ffffff;
}
QTextBrowser { border-bottom: none; }
QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QComboBox:focus { border: 2px solid $focus; padding: 6px 11px; }
QComboBox::drop-down { border: none; width: 24px; }
QComboBox::down-arrow { image: url("$chevron"); width: 12px; height: 12px; }
QComboBox QAbstractItemView { background: $layer; border: none; selection-background-color: $hover;
    selection-color: $text; outline: none; padding: 0; }
QPushButton {
    background: $secondary; color: #ffffff; border: none; border-radius: 0; padding: 9px 16px; min-height: 14px;
    text-align: left;
}
QPushButton:hover { background: $secondary_hover; }
QPushButton:focus { border: 2px solid $focus; padding: 7px 14px; }
QPushButton:disabled { background: $layer2; color: $placeholder; }
QPushButton#Primary { background: $button; color: #ffffff; font-weight: 400; }
QPushButton#Primary:hover { background: $button_hover; }
QPushButton#Primary:disabled { background: $layer2; color: $placeholder; }
QCheckBox { spacing: 8px; }
QCheckBox::indicator { width: 14px; height: 14px; border: 1px solid $text; background: transparent; }
QCheckBox::indicator:checked { background: $text; image: url("$check"); }
QCheckBox::indicator:focus { border: 2px solid $focus; }

/* ---------- data tables / lists (Carbon data table) ---------- */
QTreeWidget, QTableView, QListWidget {
    background: $layer; alternate-background-color: $layer; border: none; border-radius: 0;
    selection-background-color: $selected; selection-color: $text; outline: none;
}
QTreeWidget::item, QListWidget::item { padding: 5px 4px; border-bottom: 1px solid $border; }
QTableView::item { border-bottom: 1px solid $border; padding: 2px 4px; }
QTreeWidget::item:hover, QListWidget::item:hover, QTableView::item:hover { background: $hover; }
QTreeWidget::item:selected, QListWidget::item:selected, QTableView::item:selected { background: $selected; color: $text; }
QHeaderView { background: $layer2; }
QHeaderView::section { background: $layer2; color: $text; border: none; padding: 8px; font-weight: 600; font-size: 13px; }

/* ---------- misc ---------- */
QLabel#LinkBubble { background: $layer; color: $text; border: 1px solid $border; padding: 4px 8px; font-size: 12px; }
QLabel#Muted { color: $muted; font-size: 12px; }
QMenu { background: $layer; border: none; padding: 0; }
QMenu::item { padding: 9px 16px; border-radius: 0; }
QMenu::item:selected { background: $hover; }
QMenu::separator { height: 1px; background: $border; margin: 0; }
QToolTip { background: $text; color: $bg; border: none; padding: 4px 8px; border-radius: 2px; }
QScrollBar:vertical { background: transparent; width: 8px; margin: 0; }
QScrollBar::handle:vertical { background: $strong; min-height: 32px; }
QScrollBar:horizontal { background: transparent; height: 8px; margin: 0; }
QScrollBar::handle:horizontal { background: $strong; min-width: 32px; }
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


def stylesheet(theme: str, cache_dir: Path) -> str:
    p = PALETTES[theme]
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
    return QSS.substitute(p, sans=SANS, check=check, chevron=chevron, close=close, dclose=dclose, dfloat=dfloat)


def palette(theme: str) -> QPalette:
    p = PALETTES[theme]
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
