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
        folder = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)
        dl.setDownloadDirectory(folder)
        dl.accept()
        self.toast(f"Downloading {name}…", 0)
        dl.isFinishedChanged.connect(lambda d=dl, n=name, f=folder, rk=risky: self._download_finished(d, n, f, rk))

    def _download_finished(self, dl, name, folder, risky):
        from PySide6.QtWebEngineCore import QWebEngineDownloadRequest as DR
        if dl.state() != DR.DownloadState.DownloadCompleted:
            return
        path = os.path.join(folder, name)
        if risky:  # offer a VirusTotal hash check (no file is uploaded — we look up the SHA-256)
            self.runner.run(lambda p=path: self._sha256(p), lambda ok, h: self._offer_vt(name, h) if ok else None)
        else:
            self.toast(f"Downloaded {path}", 8000)

    @staticmethod
    def _sha256(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def _offer_vt(self, name, digest):
        ok, _ = ask(self, f"{name} downloaded",
                    "It's a file that can run code. Check its reputation on VirusTotal before you open it? "
                    "Only its fingerprint (SHA-256) is looked up; the file itself is not uploaded.",
                    "Check on VirusTotal", cancel="Not now", window_title="Download finished")
        if ok:
            self.open_url(f"https://www.virustotal.com/gui/file/{digest}", new_tab=True)
