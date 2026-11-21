#------------------------------------------------------------------------------
# Wyrm — wyrm/ui/update_runner.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""One-click updater: downloads the release for this OS and installs it in place."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, QStandardPaths, QTimer, Signal
from PySide6.QtWidgets import QApplication


class Updater(QObject):
    """One-click update (no dialog, no links): download the installer for this OS, then install in place
    (Windows: silent installer; macOS: replace the app and relaunch) and quit. Progress drives the toolbar pill."""
    progress = Signal(int)
    finished = Signal(bool, str)

    def __init__(self, win, info: dict):
        super().__init__(win)
        self.win, self.info = win, info
        self.finished.connect(self._on_finished)

    def start(self) -> bool:
        from .. import updater
        url = self.info.get("asset_url")
        if not url:
            return False
        tmp = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.TempLocation))
        dest = tmp / (self.info.get("asset_name") or "wyrm-update.bin")
        px, verify = self.win.proxies(), self.win.verify_tls()

        def work():
            updater.download(url, dest, px, verify, progress=lambda pct, *_: self.progress.emit(pct))
            return str(dest)
        self.win.runner.run(work, lambda ok, res: self.finished.emit(bool(ok), str(res)))
        return True

    def _on_finished(self, ok, res):
        from .. import updater
        if not ok:
            self.win._update_failed(f"Download failed: {res}")
            return
        try:
            updater.run_installer(Path(res))
        except Exception as e:  # noqa: BLE001
            self.win._update_failed(f"Could not start the installer: {e}")
            return
        self.win._update_restarting()
        for w in QApplication.topLevelWidgets():  # the installer needs us gone: no "Close Wyrm?" prompt
            w._force_close = True
        QTimer.singleShot(800, QApplication.instance().quit)
