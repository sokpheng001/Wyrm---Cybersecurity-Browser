#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/downloads.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Downloads: dangerous-file guard, hashing and VirusTotal lookup."""
from __future__ import annotations

import os
from html import escape

from PySide6.QtCore import QStandardPaths

from ..ui.dialogs import ask, security_warning


class DownloadsMixin:
    """Downloads: dangerous-file guard, hashing and VirusTotal lookup. (Mixed into MainWindow.)"""

    # ================================================================ downloads / lifecycle
    RISKY_EXT = {".exe", ".msi", ".msix", ".msp", ".appx", ".bat", ".cmd", ".com", ".scr", ".pif", ".ps1", ".psm1",
                 ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".jar", ".hta", ".cpl", ".dll", ".sys", ".apk",
                 ".dmg", ".pkg", ".app", ".deb", ".rpm", ".appimage", ".sh", ".run", ".bin", ".reg", ".lnk", ".url",
                 ".iso", ".img", ".vhd", ".vhdx", ".crx", ".xpi",
                 ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam"}   # Office files with macros

    def _on_download(self, dl):
        from pathlib import PurePosixPath
        url = dl.url().toString()
        name = dl.downloadFileName()
        host = dl.url().host()
        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else \
              ("." + PurePosixPath(dl.url().path()).suffix.lstrip(".").lower() if PurePosixPath(dl.url().path()).suffix else "")
        # 1. threat check: is the download source a known malware/phishing host?
        threat = self.shields.check(url, url, "MainFrame", host) if host not in self.shields.malware_allow else None
        risky = ext in self.RISKY_EXT
        if threat in ("malware", "phishing"):
            if not security_warning(
                    self, "danger", "Dangerous download blocked",
                    f"<b>{escape(name)}</b> is coming from <b>{escape(host)}</b>, a site on Wyrm's {threat} "
                    "blocklist. Files from sites like this are often used to infect computers or steal accounts.",
                    ["It may install malware, ransomware or spyware",
                     "It may steal your passwords, files or banking details"],
                    proceed="Download anyway", back="Block download"):
                dl.cancel()
                self.toast(f"Blocked download from {host} ({threat})")
                return
        elif risky:
            insecure = dl.url().scheme() == "http"
            risks = ["It can run programs and change your computer when opened",
                     "Malware often hides in files like this, even ones that look harmless"]
            if ext in {".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam"}:
                risks[0] = "It contains macros: code that runs when the document is opened"
            if ext in {".crx", ".xpi"}:
                risks[0] = "It's a browser extension: add extensions via ⋮ → Extensions, where Wyrm checks them"
            if insecure:
                risks.append("It's sent over plain HTTP, so it could have been altered on the way")
            if not security_warning(
                    self, "danger" if insecure else "caution", f"Keep {name}?",
                    f"This type of file can harm your computer. Source: <b>{escape(host or url)}</b>"
                    "<br>Only keep it if you trust this site and expected this download.",
                    risks, proceed="Keep file", back="Discard"):
                dl.cancel()
                self.toast(f"Discarded {name}")
                return
        # where to save: a configured folder, or ask each time (like other browsers). Default: ask.
        default_dir = self.settings.value("downloads/folder", "", type=str) \
            or QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
        if self.settings.value("downloads/ask", True, type=bool):
            from PySide6.QtWidgets import QFileDialog
            chosen, _ = QFileDialog.getSaveFileName(self, "Save file", os.path.join(default_dir, name))
            if not chosen:
                dl.cancel()
                self.toast("Download cancelled")
                return
            folder, name = os.path.split(chosen)
        else:
            folder = default_dir
        try:
            dl.setDownloadDirectory(folder)
            dl.setDownloadFileName(name)
        except Exception:  # noqa: BLE001 - older Qt
            pass
        dl.accept()
        self.toast(f"Downloading {name}…", 0)
        dl.isFinishedChanged.connect(lambda d=dl, n=name, f=folder, rk=risky: self._download_finished(d, n, f, rk))

    def _download_finished(self, dl, name, folder, risky):
        from PySide6.QtWebEngineCore import QWebEngineDownloadRequest as DR
        state = dl.state()
        if state == DR.DownloadState.DownloadInterrupted:
            self.toast(f"Download failed: {name} ({dl.interruptReasonString()})", 8000)
            return
        if state != DR.DownloadState.DownloadCompleted:
            return
        path = os.path.join(dl.downloadDirectory(), dl.downloadFileName())  # real path Qt used (handles renames)
        if risky:  # offer a VirusTotal hash check (no file is uploaded — we look up the SHA-256)
            self.runner.run(lambda p=path: self._sha256(p), lambda ok, h: self._offer_vt(name, h, path) if ok else None)
        else:
            self._download_done_dialog(name, path)

    def _download_done_dialog(self, name, path):
        """After a download: toast + Open / Show in folder, so the file is easy to use."""
        self.toast(f"Downloaded {name}", 8000)
        ok, _ = ask(self, f"{escape(name)} downloaded",
                    f"Saved to:<br><code>{escape(path)}</code>",
                    "Open file", cancel="Show in folder", window_title="Download finished")
        if ok:
            self._open_file(path)
        else:
            self._show_in_folder(path)

    @staticmethod
    def _open_file(path):
        import subprocess
        import sys
        try:
            if sys.platform == "win32":
                os.startfile(path)  # noqa: S606 - user asked to open their own download
            elif sys.platform == "darwin":
                subprocess.Popen(["open", path])
            else:
                subprocess.Popen(["xdg-open", path])
        except OSError:
            pass

    @staticmethod
    def _show_in_folder(path):
        import subprocess
        import sys
        try:
            if sys.platform == "win32":
                subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
            elif sys.platform == "darwin":
                subprocess.Popen(["open", "-R", path])
            else:
                subprocess.Popen(["xdg-open", os.path.dirname(path)])
        except OSError:
            pass

    @staticmethod
    def _sha256(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def _offer_vt(self, name, digest, path=""):
        ok, _ = ask(self, f"{escape(name)} downloaded",
                    f"Saved to <code>{escape(path)}</code>.<br><br>It's a file that can run code. Check its "
                    "reputation on VirusTotal before you open it? Only its fingerprint (SHA-256) is looked up; "
                    "the file itself is not uploaded.",
                    "Check on VirusTotal", cancel="Show in folder", window_title="Download finished")
        if ok:
            self.open_url(f"https://www.virustotal.com/gui/file/{digest}", new_tab=True)
        elif path:
            self._show_in_folder(path)
