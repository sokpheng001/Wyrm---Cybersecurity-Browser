#------------------------------------------------------------------------------
# Wyrm — run_qml.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Prototype launcher for the QML (Qt Quick) chrome.

Runs the new declarative UI alongside the existing QWidgets app (run.py), so we can migrate the chrome
incrementally without breaking the working browser. All logic comes from the existing Python backend via
wyrm.bridge.Bridge.

    python run_qml.py
"""
import sys
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QUrl
from PySide6.QtGui import QGuiApplication, QIcon
from PySide6.QtQml import QQmlApplicationEngine
from PySide6.QtQuickControls2 import QQuickStyle
from PySide6.QtWebEngineQuick import QtWebEngineQuick

from wyrm.bridge import Bridge
from wyrm.scheme import register_scheme

HERE = Path(__file__).parent


def main():
    QtWebEngineQuick.initialize()          # must run before the QML engine loads WebEngineView
    QCoreApplication.setOrganizationName("HackPi")
    QCoreApplication.setApplicationName("Wyrm")
    register_scheme()                      # keep wyrm:// working in the QML WebEngineView
    app = QGuiApplication(sys.argv)
    app.setWindowIcon(QIcon(str(HERE / "wyrm" / "assets" / "icon.png")))
    QQuickStyle.setStyle("Basic")          # fully QML-styleable (no native look fighting our theme)

    engine = QQmlApplicationEngine()
    bridge = Bridge()
    engine.rootContext().setContextProperty("bridge", bridge)
    engine.load(QUrl.fromLocalFile(str(HERE / "wyrm" / "qml" / "Main.qml")))
    if not engine.rootObjects():
        sys.exit("Failed to load QML")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
