#------------------------------------------------------------------------------
# Wyrm — wyrm/bridge.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Python ↔ QML bridge for the Qt Quick (QML) chrome prototype.

The QML UI stays thin: all real logic (URL resolution, theming, later the security engine) lives here in
Python and is exposed to QML as slots/properties. This proves the QML chrome can reuse every existing
backend module unchanged — only the presentation layer moves from QWidgets to QML.
"""
from __future__ import annotations

from PySide6.QtCore import Property, QObject, Signal, Slot

from . import __version__, engines, theme


class Bridge(QObject):
    def __init__(self, mode: str = "blue", theme_name: str = "dark"):
        super().__init__()
        self._mode = mode
        self._theme = theme_name

    # ---- theming exposed to QML as a map: bridge.palette.bg, bridge.palette.interactive, … ----
    @Property("QVariantMap", constant=True)
    def palette(self):
        p = dict(theme.PALETTES.get(self._theme, theme.PALETTES["dark"]))
        p["interactive"] = theme.MODE_ACCENT.get(self._mode, p.get("interactive", "#0f62fe"))
        return p

    @Property(str, constant=True)
    def version(self):
        return __version__

    @Property(str, constant=True)
    def homeUrl(self):
        return "wyrm://home"

    # ---- behaviour reused from the existing backend ----
    @Slot(str, result=str)
    def resolve(self, text: str) -> str:
        """Turn an address-bar entry into a URL exactly like the QWidgets browser does."""
        text = (text or "").strip()
        if not text:
            return "wyrm://home"
        return engines.resolve(text)

    @Slot(str, result=str)
    def prettyHost(self, url: str) -> str:
        from urllib.parse import urlparse
        u = urlparse(url)
        if u.scheme == "wyrm":
            return "New tab"
        return u.hostname or url
