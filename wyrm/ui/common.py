#------------------------------------------------------------------------------
# Wyrm — wyrm/ui/common.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Shared UI constants and the line-icon set used by the browser chrome."""
from __future__ import annotations

from PySide6.QtCore import QByteArray, Qt
from PySide6.QtGui import QIcon, QPainter, QPixmap
from PySide6.QtSvg import QSvgRenderer


HOME = "wyrm://home"


APP = "Wyrm Browser"


ICONS = {
    "back": "<path d='M19 12H5'/><path d='M12 19l-7-7 7-7'/>",
    "forward": "<path d='M5 12h14'/><path d='M12 5l7 7-7 7'/>",
    "reload": "<path d='M21 12a9 9 0 1 1-2.64-6.36'/><path d='M21 3v6h-6'/>",
    "stop": "<path d='M18 6L6 18M6 6l12 12'/>",
    "home": "<path d='M3 11l9-8 9 8'/><path d='M5 10v10h5v-6h4v6h5V10'/>",
    "plus": "<path d='M12 5v14M5 12h14'/>",
    "download": "<path d='M12 4v11'/><path d='M7 10l5 5 5-5'/><path d='M5 20h14'/>",
    "book": "<path d='M4 19.5A2.5 2.5 0 0 1 6.5 17H20V3H6.5A2.5 2.5 0 0 0 4 5.5z'/><path d='M4 19.5V21h16'/>",
    "search": "<circle cx='11' cy='11' r='7'/><path d='M21 21l-4.3-4.3'/>",
    "clock": "<circle cx='12' cy='12' r='9'/><path d='M12 7v5l3 2'/>",
    "lock": "<rect x='5' y='11' width='14' height='10' rx='2'/><path d='M8 11V7a4 4 0 0 1 8 0v4'/>",
    "unlock": "<rect x='5' y='11' width='14' height='10' rx='2'/><path d='M8 11V7a4 4 0 0 1 7.5-2'/>",
    "shield": "<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/><path d='M9 12l2 2 4-4'/>",
    "moon": "<path d='M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z'/>",
    "sun": "<circle cx='12' cy='12' r='4'/><path d='M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4'/>",
    "gear": "<circle cx='12' cy='12' r='3'/><path d='M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z'/>",
    "puzzle": "<path d='M10 3.5a2 2 0 0 1 4 0V5h4a1 1 0 0 1 1 1v4h-1.5a2 2 0 0 0 0 4H19v4a1 1 0 0 1-1 1h-4v-1.5a2 2 0 0 0-4 0V19H6a1 1 0 0 1-1-1v-4h1.5a2 2 0 0 0 0-4H5V6a1 1 0 0 1 1-1h4z'/>",
    "flag": "<path d='M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z'/><path d='M4 22v-7'/>",
    "win_min": "<path d='M7 12h10'/>",
    "win_max": "<rect x='7' y='7' width='10' height='10'/>",
    "win_restore": "<rect x='7' y='9' width='8' height='8'/><path d='M9 9V7h8v8h-2'/>",
    "win_close": "<path d='M7 7l10 10M17 7L7 17'/>",
    "shields": "<path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/><path d='M8 8l8 8'/>",
    "more": "<circle cx='12' cy='5' r='1'/><circle cx='12' cy='12' r='1'/><circle cx='12' cy='19' r='1'/>",
    "monitor": "<rect x='3' y='4' width='18' height='12'/><path d='M8 20h8M12 16v4'/>",
    "onion": "<circle cx='12' cy='13' r='8'/><circle cx='12' cy='13' r='5'/><circle cx='12' cy='13' r='2'/><path d='M12 5V2'/>",
}


def make_icon(name: str, color: str, size: int = 40) -> QIcon:
    svg = (f"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='{color}' "
           f"stroke-width='1.5' stroke-linecap='square' stroke-linejoin='miter'>{ICONS[name]}</svg>")
    renderer = QSvgRenderer(QByteArray(svg.encode()))
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    renderer.render(p)
    p.end()
    return QIcon(pm)
