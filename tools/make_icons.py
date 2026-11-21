#------------------------------------------------------------------------------
# Wyrm — tools/make_icons.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Render wyrm/assets/icon.svg into icon.png / icon.ico (Windows) / icon.icns (macOS).

    python tools/make_icons.py
"""
import io
import sys
from pathlib import Path

from PIL import Image
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, Qt
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

ASSETS = Path(__file__).resolve().parent.parent / "wyrm" / "assets"


def render(size: int) -> Image.Image:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    QSvgRenderer(QByteArray((ASSETS / "icon.svg").read_bytes())).render(p)
    p.end()
    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    img.save(buf, "PNG")
    return Image.open(io.BytesIO(bytes(buf.data()))).convert("RGBA")


def main():
    app = QGuiApplication(sys.argv)  # noqa: F841 - needed for QPainter
    big = render(1024)
    big.resize((512, 512), Image.LANCZOS).save(ASSETS / "icon.png")
    sizes = [16, 20, 24, 32, 40, 48, 64, 128, 256]
    frames = [render(s) for s in sizes]  # render each size natively for crisp small icons
    frames[-1].save(ASSETS / "icon.ico", format="ICO", sizes=[(s, s) for s in sizes], append_images=frames[:-1])
    big.save(ASSETS / "icon.icns", format="ICNS")
    print("wrote", *(p.name for p in ASSETS.glob("icon.*")))


if __name__ == "__main__":
    main()
