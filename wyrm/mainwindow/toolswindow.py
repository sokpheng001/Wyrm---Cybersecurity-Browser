#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/toolswindow.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""The Security tools detached into their own top-level window.

When the user detaches the tools, the Security panel's content is moved out of the browser window and into a
ToolsWindow. This window has no parent, so it survives closing the browser: the browser hides instead of quitting
while tools are detached, and the app only exits once the tools window is closed too. Closing the tools window
re-docks everything back into the browser, so the tools are never lost."""
from __future__ import annotations

from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMainWindow, QToolBar


class ToolsWindow(QMainWindow):
    """Hosts the detached Security panel content. `win` is the owning browser MainWindow (kept alive while this
    window is open so the tools' actions still work)."""

    def __init__(self, win, content):
        super().__init__()           # no parent: a real top-level window that outlives the browser window
        self.win = win
        self.setWindowTitle("Wyrm — Security tools")
        self.setWindowIcon(win.windowIcon())
        self.resize(560, 820)
        bar = QToolBar()
        bar.setMovable(False)
        self._act_browser = QAction("Show browser", self)
        self._act_browser.setToolTip("Bring the browser window back to the front")
        self._act_browser.triggered.connect(self._show_browser)
        bar.addAction(self._act_browser)
        redock = QAction("Re-dock into browser", self)
        redock.setToolTip("Move the tools back into the browser window")
        redock.triggered.connect(lambda: win.redock_tools())
        bar.addAction(redock)
        self.addToolBar(bar)
        self.setCentralWidget(content)

    def _show_browser(self):
        self.win.showNormal()
        self.win.raise_()
        self.win.activateWindow()

    def closeEvent(self, e):
        # never lose the tools: closing this window re-docks them into the browser (showing the browser if it was
        # hidden). redock_tools() deletes this window afterwards.
        super().closeEvent(e)
        self.win.redock_tools(show_browser=True)
