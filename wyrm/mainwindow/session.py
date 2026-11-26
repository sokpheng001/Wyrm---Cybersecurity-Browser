#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/session.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Session: reopen tabs at start, window title, close confirmation."""
from __future__ import annotations

import json
import sys

from PySide6.QtCore import QUrl

from ..ui.dialogs import ask


class SessionMixin:
    """Session: reopen tabs at start, window title, close confirmation. (Mixed into MainWindow.)"""

    # ---------------------------------------------------------------- session (reopen tabs) + close confirmation
    def _session_urls(self) -> list[str]:
        urls = []
        for i in range(self.tabbar.count()):
            u = self.tabbar.tabData(i).url().toString()
            if u and u != "about:blank" and not u.startswith(("data:", "view-source:")):
                urls.append(u)
        return urls

    def _save_session(self):
        if self.ephemeral or getattr(self, "_new_window", False) \
                or not self.settings.value("general/restore_tabs", False, type=bool):
            return  # only persist when "Reopen last session" is on (and not Tor/private/second window)
        self.settings.setValue("session/tabs", json.dumps(self._session_urls()))
        self.settings.setValue("session/current", self.tabbar.currentIndex())
        self.settings.sync()

    def _restore_session(self) -> bool:
        if self.ephemeral or not self.settings.value("general/restore_tabs", False, type=bool):
            return False   # respect "Reopen last session's tabs on startup"
        try:
            urls = [u for u in json.loads(self.settings.value("session/tabs", "[]") or "[]") if isinstance(u, str)]
        except ValueError:
            urls = []
        if not urls:
            return False
        for u in urls[:50]:
            self.new_tab(QUrl(u))
        cur = self.settings.value("session/current", 0, type=int)
        if 0 <= cur < self.tabbar.count():
            self.tabbar.setCurrentIndex(cur)
        return True

    def _set_title(self, text: str):
        # macOS: the tab strip is the title bar, so no title text is drawn there. (A single space, because Qt
        # substitutes the app name for an empty title.) Other OSes: normal window title for the taskbar.
        self.setWindowTitle(" " if sys.platform == "darwin" else text)

    def _confirm_close(self) -> bool:
        if getattr(self, "_force_close", False) or not self.settings.value("ui/confirm_close", True, type=bool):
            return True
        n = self.tabbar.count()
        tabs = f"{n} tab{'s' if n != 1 else ''}"
        if self.tor:
            title, body = "Close this Tor window?", f"{tabs} will be closed. Nothing from this window is saved."
        elif self.private:
            title = "Close this private window?"
            body = (f"{tabs} will be closed and this window's history, cookies and site data deleted. "
                    "Downloads are kept.")
        else:
            title = "Close Wyrm Browser?"
            if self.settings.value("general/restore_tabs", False, type=bool):
                body = f"You have {tabs} open. They'll be reopened the next time you start Wyrm Browser."
            else:
                body = (f"You have {tabs} open. They won't be reopened — turn on "
                        "“Reopen last session's tabs” in Settings if you want that.")

        ok, dont = ask(self, title, body, "Close", checkbox="Don't ask again", window_title="Close Wyrm Browser")
        if not ok:
            return False
        if dont:
            self.settings.setValue("ui/confirm_close", False)
        return True

    def closeEvent(self, e):
        # While the tools are popped out into their own window, closing the browser must not quit the app or the
        # tools would vanish. Hide the browser instead and keep the process alive; the tools window stays open,
        # and re-docking (or closing that window) brings the browser back.
        if self.tools_detached() and not self._tools_window.isHidden():
            e.ignore()
            self.hide()
            return
        if not self._confirm_close():
            e.ignore()
            return
        # Flush everything that must persist, up front, so we can exit without a slow graceful teardown.
        self._save_session()
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("sec/visible", self.security.isVisible())
        self.settings.sync()
        self.runner.shutdown()
        if getattr(self, "bg_video_server", None) is not None:
            self.bg_video_server.stop()
        if getattr(self.security, "oob", None) is not None:
            self.security.oob.shutdown()  # stop the OOB interaction listener
        pending = getattr(self, "_pending_update", None)
        from PySide6.QtWidgets import QApplication
        others = [w for w in QApplication.topLevelWidgets()
                  if w is not self and isinstance(w, type(self)) and not w.isHidden()]
        # Fast path — the common case: a single normal window with nothing to install. Exit the process
        # immediately instead of waiting on Qt / Qt WebEngine / background-thread teardown (that wait is what made
        # closing feel slow compared with other browsers). All state is already flushed to disk above.
        if not others and not pending and not self.tor and not self.ephemeral:
            import os
            os._exit(0)
        if pending:
            self._install_pending_on_close()  # "Later" update: installs now that the browser is closing
        self._ext_shutdown()  # switch extensions off first: Qt crashes tearing down profiles with them on
        self.tabbar.blockSignals(True)
        while self.tabbar.count():
            view = self.tabbar.tabData(0)
            self.tabbar.removeTab(0)
            view.page().deleteLater()
        super().closeEvent(e)
