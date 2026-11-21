#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/extensions.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Browser extensions: the Extensions menu, the manager dialog and loading the library into profiles.

Extensions live unpacked in <data>/extensions/ (see wyrm/extensions.py) and are loaded into every normal
profile (personal + each engagement). Qt loads extensions disabled, so the ones the user switched on are
remembered in settings ("extensions/enabled") and re-enabled as each one finishes loading. Private and Tor
windows never run extensions (Qt doesn't support them in off-the-record profiles, and they could leak data).
"""
from __future__ import annotations

import shutil
from pathlib import Path

from PySide6.QtCore import QPoint, QTimer, Qt
from PySide6.QtWidgets import (QCheckBox, QDialog, QFileDialog, QHBoxLayout, QInputDialog, QLabel, QListWidget,
                               QListWidgetItem, QPushButton, QVBoxLayout, QWidget)

from .. import extensions as ext


class ExtensionsMixin:
    """Browser extensions (Chrome-compatible, Manifest V3). (Mixed into MainWindow.)"""

    # ---------------------------------------------------------------- library + profiles
    def _ext_supported(self) -> bool:
        from PySide6.QtWebEngineCore import QWebEngineProfile
        return hasattr(QWebEngineProfile, "extensionManager") and not self.ephemeral

    def _ext_lib(self) -> Path:
        return self.data_dir / ext.LIB_DIR

    def _ext_enabled(self) -> set[str]:
        v = self.settings.value("extensions/enabled", [], type=list) or []
        return {str(x) for x in v}

    def _ext_save_enabled(self, folders: set[str]):
        self.settings.setValue("extensions/enabled", sorted(folders))

    def _ext_managers(self) -> list:
        out = []
        for key, prof in self.profiles.items():
            if key in ("tor", "private"):
                continue
            mgr = prof.extensionManager() if hasattr(prof, "extensionManager") else None
            if mgr is not None:
                out.append(mgr)
        return out

    def _ext_attach(self, prof):
        """Load the extension library into a newly created (normal) profile."""
        if not self._ext_supported():
            return
        mgr = prof.extensionManager()
        if mgr is None:
            return
        self._ext_purge_removed()
        mgr.loadFinished.connect(lambda info, m=mgr: self._ext_loaded(m, info))
        mgr.unloadFinished.connect(lambda info: self._ext_purge_removed())
        for e in ext.library(self._ext_lib()):
            mgr.loadExtension(str(e["path"]))

    @staticmethod
    def _ext_folder(info) -> str:
        return Path(info.path()).name if info.path() else ""

    def _ext_info(self, mgr, folder: str):
        return next((i for i in mgr.extensions() if self._ext_folder(i) == folder), None)

    def _ext_loaded(self, mgr, info):
        folder = self._ext_folder(info)
        if not info.isLoaded():
            if folder and (self._ext_lib() / folder).is_dir():
                self.toast(f"Extension {info.name() or folder} could not load: {info.error()}", 8000)
            return
        if folder in self._ext_enabled() and not info.isEnabled():
            # not from inside Qt's own signal handler: re-enter the manager once the event loop is back
            QTimer.singleShot(0, lambda m=mgr, f=folder: self._ext_enable_now(m, f))

    def _ext_enable_now(self, mgr, folder: str):
        info = self._ext_info(mgr, folder)
        if info is not None and info.isLoaded() and not info.isEnabled() and folder in self._ext_enabled():
            mgr.setExtensionEnabled(info, True)

    def _ext_load_everywhere(self, folder: str, enable: bool = True):
        if enable:
            self._ext_save_enabled(self._ext_enabled() | {folder})
        path = str(self._ext_lib() / folder)
        for mgr in self._ext_managers():
            old = self._ext_info(mgr, folder)
            if old is not None:   # re-added (e.g. updated): reload from the new files
                mgr.unloadExtension(old)
            mgr.loadExtension(path)

    def _ext_set_enabled(self, folder: str, on: bool):
        en = self._ext_enabled()
        self._ext_save_enabled(en | {folder} if on else en - {folder})
        for mgr in self._ext_managers():
            info = self._ext_info(mgr, folder)
            if info is not None and info.isEnabled() != on:
                mgr.setExtensionEnabled(info, on)

    def _ext_remove(self, folder: str):
        self._ext_save_enabled(self._ext_enabled() - {folder})
        pending = set(self.settings.value("extensions/removed", [], type=list) or [])
        self.settings.setValue("extensions/removed", sorted(pending | {folder}))
        unloading = False
        for mgr in self._ext_managers():
            info = self._ext_info(mgr, folder)
            if info is not None:
                mgr.unloadExtension(info)  # files are deleted once it's unloaded (unloadFinished)
                unloading = True
        if not unloading:
            self._ext_purge_removed()

    def _ext_purge_removed(self):
        """Delete removed extensions' files (on Windows they stay locked until unloaded, so retried later)."""
        pending = [str(x) for x in (self.settings.value("extensions/removed", [], type=list) or [])]
        left = []
        for folder in pending:
            d = self._ext_lib() / folder
            if any(self._ext_info(m, folder) for m in self._ext_managers()):
                left.append(folder)
                continue
            shutil.rmtree(d, ignore_errors=True)
            if d.exists():
                left.append(folder)
        self.settings.setValue("extensions/removed", left)

    def _ext_add(self, source, ext_id: str | None = None, on_done=None):
        """Unpack an extension in the background, then load + enable it in every normal profile."""
        lib = self._ext_lib()
        px, verify = self.proxies(), self.verify_tls()  # read on the UI thread
        self.toast("Adding extension…", 3000)

        def work():  # download + unpack + validate into a staging folder; nothing is installed yet
            if source == "store":
                data = ext.download_from_store(ext_id, px, verify)
                return ext.prepare(lib, data, ext_id)
            return ext.prepare(lib, Path(source), ext_id)

        def done(ok, res):
            if not ok:
                msg = str(res) if isinstance(res, ext.ExtensionError) else f"Could not add the extension: {res}"
                self.toast(msg, 9000)
                if on_done:
                    on_done(False, msg)
                return
            staged, folder, manifest = res
            name = ext.localized(staged, manifest, "name") or folder
            # Wyrm Shield: say exactly what the extension will be able to do before installing it
            level, risks = ext.assess(manifest)
            origin = ("from the Chrome Web Store" if source == "store"
                      else "from a file on your computer, <b>not</b> from the Chrome Web Store. "
                           "Only add it if you trust whoever gave it to you")
            body = (f"<b>{_esc(name)}</b> {_esc(str(manifest.get('version', '')))} comes {origin}."
                    "<br><br>If you add it, it will be able to:")
            if not risks:
                body = (f"<b>{_esc(name)}</b> comes {origin}. It asks for no special permissions.")
            from ..ui.dialogs import security_warning
            if not security_warning(self, level, f"Add “{name}”?", body, risks,
                                    proceed="Add extension", back="Cancel"):
                ext.discard(lib)
                self.toast(f"Not added: {name}", 4000)
                if on_done:
                    on_done(False, "cancelled")
                return
            try:
                ext.commit(lib, staged, folder)
            except OSError as e:
                ext.discard(lib)
                self.toast(f"Could not add the extension: {e}", 9000)
                return
            pending = set(self.settings.value("extensions/removed", [], type=list) or []) - {folder}
            self.settings.setValue("extensions/removed", sorted(pending))
            self._ext_load_everywhere(folder, enable=True)
            self.toast(f"Added extension: {name}", 5000)
            if on_done:
                on_done(True, name)
        self.runner.run(work, done)

    # ---------------------------------------------------------------- Chrome Web Store pages
    STORE_HOSTS = ("chromewebstore.google.com", "chrome.google.com")

    def _ext_store_check(self, url):
        """On a Chrome Web Store extension page, show Wyrm's own "Add to Wyrm Browser" bar: the store greys out
        its "Add to Chrome" button in other browsers (and that button only works inside Google Chrome)."""
        banner = getattr(self, "store_banner", None)
        if banner is None:
            return
        ext_id = None
        if url.scheme() == "https" and url.host() in self.STORE_HOSTS and "/detail/" in url.path() \
                and (url.host() != "chrome.google.com" or url.path().startswith("/webstore/")):
            ext_id = ext.store_id(url.path().rstrip("/").rsplit("/", 1)[-1])  # the ID is the last path part
        if not ext_id or not self._ext_supported():
            if ext_id and self.ephemeral:
                banner.show_banner(True, "Extensions can't be added in private or Tor windows. Open this page in "
                                         "a normal Wyrm window to add it.", "OK", lambda: banner.show_banner(False))
                return
            banner.show_banner(False)
            return
        have = (self._ext_lib() / ext_id / "manifest.json").is_file()
        text = ("<b>Wyrm Browser</b> can add this extension (the store's “Add to Chrome” button only works in "
                "Google Chrome)." if not have else "This extension is already in Wyrm Browser.")
        banner.show_banner(True, text, "Reinstall" if have else "Add to Wyrm Browser",
                           lambda i=ext_id: self._ext_add("store", i))
        banner.button.setEnabled(True)

    # ---------------------------------------------------------------- menu + popups
    def _ext_fill_menu(self, menu):
        """Rebuilt each time the Extensions submenu opens: enabled extensions (click = its popup) + Manage."""
        menu.clear()
        if not self._ext_supported():
            a = menu.addAction("Extensions are off in private and Tor windows" if self.ephemeral
                               else "Extensions need a newer Qt WebEngine (6.10+)")
            a.setEnabled(False)
            return
        mgr = self.profile.extensionManager() if hasattr(self.profile, "extensionManager") else None
        enabled = self._ext_enabled()
        shown = 0
        for e in ext.library(self._ext_lib()):
            if e["folder"] not in enabled:
                continue
            info = self._ext_info(mgr, e["folder"]) if mgr else None
            popup = info.actionPopupUrl() if info is not None else None
            a = menu.addAction(e["name"])
            if popup is not None and popup.isValid() and not popup.isEmpty():
                a.triggered.connect(lambda _c=False, u=popup, n=e["name"]: self._ext_popup(u, n))
            else:
                a.setEnabled(False)  # runs in the background / on pages; no popup to open
            shown += 1
        if not shown:
            a = menu.addAction("No extensions switched on")
            a.setEnabled(False)
        menu.addSeparator()
        menu.addAction("Manage extensions…", self.manage_extensions)

    def _ext_popup(self, url, name: str):
        """An extension's toolbar popup, shown under the top-right of the window like in Chrome."""
        from PySide6.QtWebEngineCore import QWebEnginePage
        from PySide6.QtWebEngineWidgets import QWebEngineView
        old = getattr(self, "_ext_pop", None)
        if old is not None:
            old.close()
        view = QWebEngineView()
        view.setWindowFlags(Qt.WindowType.Popup)
        view.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        view.setWindowTitle(name)
        view.setPage(QWebEnginePage(self.profile, view))
        view.resize(380, 560)
        top_right = self.mapToGlobal(QPoint(self.width() - 396, 96))
        view.move(top_right)
        view.load(url)
        view.show()
        self._ext_pop = view

    # ---------------------------------------------------------------- manager dialog
    def manage_extensions(self):
        if not self._ext_supported():
            from ..ui.dialogs import ask
            ask(self, "Extensions aren't available here",
                "Private and Tor windows never run extensions. Open a normal window to manage them."
                if self.ephemeral else "This build's Qt WebEngine is too old for extensions (6.10 or newer is needed).",
                "OK", cancel="Close")
            return
        d = QDialog(self, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
        d.setObjectName("ConfirmDialog")
        d.setWindowTitle("Extensions")
        d.setMinimumSize(560, 460)
        v = QVBoxLayout(d)
        v.setContentsMargins(28, 24, 28, 22)
        v.setSpacing(10)
        head = QLabel("Extensions")
        head.setObjectName("DialogTitle")
        v.addWidget(head)
        note = QLabel("Chrome extensions (Manifest V3). Add one from the Chrome Web Store, a .zip / .crx file, "
                      "or an unpacked folder. Extensions run in normal windows only, never in private or Tor "
                      "windows. Only add extensions you trust: they can read the pages you visit.")
        note.setObjectName("Muted")
        note.setWordWrap(True)
        v.addWidget(note)
        lst = QListWidget()
        lst.setObjectName("ExtList")
        v.addWidget(lst, 1)

        def refresh():
            lst.clear()
            items = ext.library(self._ext_lib())
            pending = set(self.settings.value("extensions/removed", [], type=list) or [])
            items = [e for e in items if e["folder"] not in pending]
            if not items:
                it = QListWidgetItem("No extensions yet. Use the buttons below to add one.")
                it.setFlags(Qt.ItemFlag.NoItemFlags)
                lst.addItem(it)
                return
            enabled = self._ext_enabled()
            for e in items:
                row = QWidget()
                h = QHBoxLayout(row)
                h.setContentsMargins(8, 6, 8, 6)
                txt = QLabel(f"<b>{_esc(e['name'])}</b> <span style='color:gray'>{_esc(e['version'])}</span>"
                             f"<br><span style='color:gray'>{_esc(e['description'][:160])}</span>")
                txt.setWordWrap(True)
                h.addWidget(txt, 1)
                on = QCheckBox("On")
                on.setChecked(e["folder"] in enabled)
                on.toggled.connect(lambda c, f=e["folder"]: self._ext_set_enabled(f, c))
                h.addWidget(on)
                rm = QPushButton("Remove")
                rm.clicked.connect(lambda _c=False, f=e["folder"]: (self._ext_remove(f), refresh()))
                h.addWidget(rm)
                it = QListWidgetItem()
                it.setSizeHint(row.sizeHint())
                lst.addItem(it)
                lst.setItemWidget(it, row)

        def after_add(ok, _msg):
            refresh()

        def from_store():
            text, ok = QInputDialog.getText(d, "Add from Chrome Web Store",
                                            "Paste the extension's Chrome Web Store link (or its 32-letter ID):")
            if not ok or not text.strip():
                return
            ext_id = ext.store_id(text)
            if not ext_id:
                self.toast("That isn't a Chrome Web Store extension link or ID.", 6000)
                return
            self._ext_add("store", ext_id, on_done=after_add)

        def from_file():
            path, _ = QFileDialog.getOpenFileName(d, "Add extension", str(Path.home() / "Downloads"),
                                                  "Extensions (*.zip *.crx)")
            if path:
                self._ext_add(path, on_done=after_add)

        def from_folder():
            path = QFileDialog.getExistingDirectory(d, "Add unpacked extension (folder with manifest.json)",
                                                    str(Path.home()))
            if path:
                self._ext_add(path, on_done=after_add)

        row = QHBoxLayout()
        row.setSpacing(8)
        for label, fn in (("Chrome Web Store…", from_store), (".zip / .crx file…", from_file),
                          ("Unpacked folder…", from_folder)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            row.addWidget(b)
        row.addStretch(1)
        close = QPushButton("Done")
        close.setObjectName("Primary")
        close.setDefault(True)
        close.clicked.connect(d.accept)
        row.addWidget(close)
        v.addLayout(row)
        refresh()
        d.exec()


def _esc(s: str) -> str:
    from html import escape
    return escape(str(s or ""))
