#------------------------------------------------------------------------------
# Wyrm — wyrm/favicons.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Search-engine logos (site favicons) for the engine dropdown.

Each icon is downloaded once via DuckDuckGo's icon service (falling back to the engine's own /favicon.ico), decoded
and re-encoded as PNG by Qt, and cached in the data folder; after that no request is made. Until an icon is
available a neutral monogram is shown, so the list never jumps.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import requests
from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import QColor, QFont, QIcon, QImage, QPainter, QPixmap

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Wyrm/1.0"}
MAX_BYTES = 512 * 1024


def cache_file(cache_dir: Path, key: str) -> Path:
    return cache_dir / f"{key}.png"


def cached_icon(cache_dir: Path, key: str) -> QIcon | None:
    f = cache_file(cache_dir, key)
    if f.is_file():
        img = QImage(str(f))
        if not img.isNull():
            return QIcon(QPixmap.fromImage(img))
    return None


def monogram(name: str, color: str = "#8d8d8d", size: int = 32) -> QIcon:
    """Placeholder: first letter in a rounded square."""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(color))
    p.drawRoundedRect(QRectF(0, 0, size, size), size * 0.22, size * 0.22)
    f = QFont()
    f.setPixelSize(int(size * 0.55))
    f.setBold(True)
    p.setFont(f)
    p.setPen(QColor("#ffffff"))
    p.drawText(QRectF(0, 0, size, size), Qt.AlignmentFlag.AlignCenter, (name[:1] or "?").upper())
    p.end()
    return QIcon(pm)


def fetch(home: str, proxies=None, verify=True) -> bytes | None:
    """Raw favicon bytes for a site (worker thread): DuckDuckGo's icon service, then the site's /favicon.ico."""
    host = urlparse(home).hostname
    if not host:
        return None
    # DuckDuckGo's icon service returns the icon the site declares (<link rel=icon>), which is usually
    # better than a legacy /favicon.ico; fall back to the site itself.
    for url in (f"https://icons.duckduckgo.com/ip3/{host}.ico", f"https://{host}/favicon.ico"):
        try:
            r = requests.get(url, headers=UA, timeout=10, proxies=proxies, verify=verify)
            if r.ok and 0 < len(r.content) <= MAX_BYTES:
                return r.content
        except requests.RequestException:
            continue
    return None


def store(cache_dir: Path, key: str, data: bytes) -> QIcon | None:
    """Decode (UI thread), normalise to a 32px PNG in the cache, and return the icon; None if not an image."""
    img = QImage()
    if not data or not img.loadFromData(QByteArray(data)) or img.isNull():
        return None
    img = img.scaled(32, 32, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
    cache_dir.mkdir(parents=True, exist_ok=True)
    img.save(str(cache_file(cache_dir, key)), "PNG")
    return QIcon(QPixmap.fromImage(img))
