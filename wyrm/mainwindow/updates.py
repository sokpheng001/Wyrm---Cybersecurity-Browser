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
        """Update pill clicked: download (progress on the pill), then ask to restart now or later."""
        if getattr(self, "_pending_update", None):  # already downloaded ("Later" was chosen): ask again
            self._ask_restart()
            return
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

    def _update_ready(self, path):
        """Update downloaded: keep it and ask whether to restart now or later."""
        self._updater = None
        self._pending_update = path
        self.b_update.setEnabled(True)
        self.b_update.setText("  Restart to update")
        self.b_update.setToolTip("The update is downloaded. Click to restart Wyrm Browser and finish updating — "
                                 "or just keep browsing: it installs when you close the browser.")
        self._ask_restart()

    def _ask_restart(self):
        from PySide6.QtWidgets import QMessageBox
        from ..ui.update_runner import install_and_quit
        ver = (self._update_info or {}).get("version", "")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setText(f"Wyrm Browser {ver} is ready to install")
        box.setInformativeText("Restart now to finish updating and get the latest features. Your open tabs will "
                               "reopen.\n\nChoose Later to keep browsing — the update installs when you close "
                               "Wyrm Browser.")
        now = box.addButton("Restart now", QMessageBox.ButtonRole.AcceptRole)
        box.addButton("Later", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(now)
        box.exec()
        if box.clickedButton() is now:
            path, self._pending_update = self._pending_update, None
            self._save_session()  # tabs come back after the restart
            self._update_restarting()
            if not install_and_quit(self, path, relaunch=True):
                self._pending_update = path
        else:
            self.toast("OK — the update will install when you close Wyrm Browser. "
                       "Click “Restart to update” any time.", 6000)

    def _install_pending_on_close(self):
        """Called while closing: a downloaded update chosen "Later" is installed now (no relaunch)."""
        path = getattr(self, "_pending_update", None)
        if path:
            from ..ui.update_runner import install_and_quit
            self._pending_update = None
            install_and_quit(self, path, relaunch=False)
