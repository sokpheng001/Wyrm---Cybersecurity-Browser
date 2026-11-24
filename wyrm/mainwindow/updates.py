#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/updates.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Update checks and the one-click Update button."""
from __future__ import annotations

from html import escape

from PySide6.QtWidgets import QMessageBox

from .. import __build__, __version__, version_label
from ..ui.update_runner import Updater
from ..updater import _ver_tuple


class UpdatesMixin:
    """Update checks and the one-click Update button. (Mixed into MainWindow.)"""

    def _check_updates(self, manual=True):
        from .. import updater
        if manual:
            self.toast("Checking for updates…", 3000)
        px, verify = self.proxies(), self.verify_tls()
        self.runner.run(lambda: updater.check(__version__, px, verify, __build__),
                        lambda ok, r: self._updates_checked(ok, r, manual))

    # ---- Wyrm update policy (so users aren't nagged to click "Update" on every push) ----
    # A routine update (same MAJOR.MINOR — a patch or a new build, which is most pushes) that isn't unusually
    # large installs SILENTLY: it downloads in the background and is applied the next time Wyrm is restarted.
    # A feature update (MINOR or MAJOR version bump) or an unusually large download is USER-CHOSEN: the Update
    # button appears and the user decides when. A manual "Check for updates…" always offers to update now.
    LARGE_UPDATE_BYTES = 400 * 1024 * 1024

    def _update_kind(self, info) -> str:
        cur = _ver_tuple(__version__)
        new = _ver_tuple(info.get("version", ""))
        if new[:2] != cur[:2]:
            return "feature"
        if int(info.get("asset_size", 0) or 0) > self.LARGE_UPDATE_BYTES:
            return "feature"
        return "auto"

    def _updates_checked(self, ok, info, manual):
        if not ok:
            if manual:
                QMessageBox.warning(self, "Updates", f"Could not check for updates:\n{info}")
            return
        if not info.get("newer"):
            self._update_info = None
            self.b_update.hide()
            if manual:
                QMessageBox.information(self, "Updates", f"You're on the latest version ({version_label()}).")
            return
        if getattr(self, "_updater", None) or getattr(self, "_pending_update", None):
            return  # already downloading or downloaded
        self._update_info = info
        kind = self._update_kind(info)
        # Always show the Update button so the user knows an update is available — even routine build bumps.
        from .. import updater
        changes = updater.whats_new(info.get("notes", ""))
        tip = (f"<b>Wyrm Browser {escape(info.get('version', ''))}</b> is available (you have {version_label()}).<br>"
               "Click to update now — or it installs automatically when you restart Wyrm.")
        if changes:
            tip += "<br><br><b>What's new</b><ul style='margin:4px 0 0 -18px'>" + \
                   "".join(f"<li>{escape(c)}</li>" for c in changes) + "</ul>"
        self.b_update.setText("  Update")
        self.b_update.setEnabled(True)
        self.b_update.setToolTip(tip)
        self.b_update.show()
        if kind == "auto" and not manual:
            # routine update: download quietly in the background now; it still installs on restart. The button is
            # just the heads-up (no forced dialog), so the user always knows an update is waiting.
            self._auto_update = True
            self._updater = Updater(self, info)
            if not self._updater.start():
                self._updater = None
                self._auto_update = False
        else:
            self._auto_update = False
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
        if getattr(self, "_auto_update", False):  # routine update download failed: keep the button so they can retry
            self._auto_update = False
            self.b_update.setEnabled(True)
            self.b_update.setText("  Update")
            return
        self.b_update.setEnabled(True)
        self.b_update.setText("  Update failed — retry")
        self.toast(msg, 6000)

    def _update_restarting(self):
        self.b_update.setText("  Restarting…")

    def _update_ready(self, path):
        """Update downloaded. Silent (auto) updates just wait for the next restart; feature updates ask now."""
        self._updater = None
        self._pending_update = path
        if getattr(self, "_auto_update", False):
            # routine update downloaded: show "Restart to update" so the user can finish now if they want — but
            # don't force a dialog; it still installs automatically when Wyrm is next closed/restarted.
            self.b_update.setEnabled(True)
            self.b_update.setText("  Restart to update")
            self.b_update.setToolTip("Update downloaded — click to restart and finish now, or it installs when you "
                                     "close Wyrm.")
            self.b_update.show()
            self.toast("Update downloaded — it installs when you restart Wyrm (or click “Restart to update”).", 7000)
            return
        self.b_update.setEnabled(True)
        self.b_update.setText("  Restart to update")
        self.b_update.setToolTip("The update is downloaded. Click to restart Wyrm Browser and finish updating — "
                                 "or just keep browsing: it installs when you close the browser.")
        self._ask_restart()

    def _ask_restart(self):
        from ..ui.dialogs import ask
        from ..ui.update_runner import install_and_quit
        ver = (self._update_info or {}).get("version", "")
        now, _ = ask(self, f"Wyrm Browser {ver} is ready to install",
                     "Restart now to finish updating and get the latest features. Your open tabs will reopen. "
                     "Choose Later to keep browsing: the update installs when you close Wyrm Browser.",
                     "Restart now", cancel="Later", window_title="Update Wyrm Browser")
        if now:
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
