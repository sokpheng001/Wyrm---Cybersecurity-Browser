#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/tor.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Tor windows: open, new identity, disconnect."""
from __future__ import annotations

import sys

from PySide6.QtCore import QProcess
from PySide6.QtWidgets import QMessageBox


class TorMixin:
    """Tor windows: open, new identity, disconnect. (Mixed into MainWindow.)"""

    # ================================================================ Tor / private windows
    def open_private_window(self):
        """Private window (like incognito): separate process with an in-memory profile; nothing is saved."""
        args = (["--private"] if getattr(sys, "frozen", False) else [sys.argv[0], "--private"])
        QProcess.startDetached(sys.executable, args)
        self.toast("Opening a private window — nothing you do there is saved.")

    def open_tor_window(self):
        args = (["--tor"] if getattr(sys, "frozen", False) else [sys.argv[0], "--tor"])
        QProcess.startDetached(sys.executable, args)
        self.toast("Opening a Tor window… connecting to the Tor network can take a minute.")

    def tor_new_identity(self):
        try:
            self.tor.new_identity()
            for i in range(self.tabbar.count()):
                self.tabbar.tabData(i).reload()
            self.toast("New Tor identity: new circuits for all tabs")
        except Exception as e:  # noqa: BLE001
            self.toast(f"Couldn't get a new identity: {e}")

    def disconnect_tor(self):
        """Close the Tor window and tear down the Tor process (the window IS the Tor session)."""
        if not self.tor:
            return
        if QMessageBox.question(self, "Disconnect Tor",
                                "Disconnect from the Tor network and close this private window?",
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes:
            self._force_close = True
            self.close()  # app.aboutToQuit → tor.stop() tears down the Tor process
