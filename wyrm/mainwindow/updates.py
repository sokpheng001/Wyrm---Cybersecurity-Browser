#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/updates.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Update checks and the one-click Update button."""
from __future__ import annotations

from html import escape

from PySide6.QtWidgets import QMessageBox

from .. import __build__, __version__, version_label
from ..ui.update_runner import Updater


class UpdatesMixin:
    """Update checks and the one-click Update button. (Mixed into MainWindow.)"""

    def _check_updates(self, manual=True):
        from .. import updater
        if manual:
            self.toast("Checking for updates…", 3000)
        px, verify = self.proxies(), self.verify_tls()
        self.runner.run(lambda: updater.check(__version__, px, verify, __build__),
                        lambda ok, r: self._updates_checked(ok, r, manual))

    def _updates_checked(self, ok, info, manual):
        if not ok:
            if manual:
                QMessageBox.warning(self, "Updates", f"Could not check for updates:\n{info}")
            return
        if not info.get("newer"):
            self._update_info = None
            self.b_update.hide()  # nothing new: no button
            if manual:
                QMessageBox.information(self, "Updates", f"You're on the latest version ({version_label()}).")
            return
        if getattr(self, "_updater", None):  # already updating
            return
        self._update_info = info
        self.b_update.setText("  Update")
        self.b_update.setEnabled(True)
        from .. import updater
        changes = updater.whats_new(info.get("notes", ""))
        tip = (f"<b>Wyrm Browser {escape(info.get('version', ''))}</b> is available (you have {version_label()}).<br>"
               "Click to update — it installs and restarts automatically.")
        if changes:
            tip += "<br><br><b>What's new</b><ul style='margin:4px 0 0 -18px'>" + \
                   "".join(f"<li>{escape(c)}</li>" for c in changes) + "</ul>"
        self.b_update.setToolTip(tip)
        self.b_update.show()
        if manual:
            self.toast(f"Wyrm Browser {info.get('version')} is available — click Update at the top right.", 6000)

    def _open_update(self):
        """Update pill clicked: download + install right away, progress shown on the pill."""
        if not self._update_info or getattr(self, "_updater", None):
            return
        self._updater = Updater(self, self._update_info)
        if not self._updater.start():
            self._updater = None
            self.toast("This update has no installer for your system yet.", 5000)
            return
        self.b_update.setEnabled(False)
        self.b_update.setText("  Updating 0%")
        self._updater.progress.connect(lambda pct: self.b_update.setText(f"  Updating {pct}%"))

    def _update_failed(self, msg: str):
        self._updater = None
        self.b_update.setEnabled(True)
        self.b_update.setText("  Update failed — retry")
        self.toast(msg, 6000)

    def _update_restarting(self):
        self.b_update.setText("  Restarting…")
