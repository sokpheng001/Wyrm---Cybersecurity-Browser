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
from PySide6.QtWidgets import QMessageBox


class DownloadsMixin:
    """Downloads: dangerous-file guard, hashing and VirusTotal lookup. (Mixed into MainWindow.)"""

    # ================================================================ downloads / lifecycle
    RISKY_EXT = {".exe", ".msi", ".msix", ".bat", ".cmd", ".com", ".scr", ".pif", ".ps1", ".vbs", ".vbe",
                 ".js", ".jse", ".jar", ".hta", ".cpl", ".dll", ".apk", ".dmg", ".pkg", ".deb", ".rpm",
                 ".sh", ".run", ".reg", ".lnk", ".iso", ".img"}

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
            m = QMessageBox(self)
            m.setIcon(QMessageBox.Icon.Critical)
            m.setWindowTitle("Dangerous download blocked")
            m.setText(f"<b>{escape(name)}</b> is being downloaded from <b>{escape(host)}</b>, which is on a "
                      f"{threat} blocklist.")
            m.setInformativeText("This file may be malware. Downloading is strongly discouraged.")
            keep = m.addButton("Download anyway", QMessageBox.ButtonRole.DestructiveRole)
            m.addButton("Block", QMessageBox.ButtonRole.RejectRole)
            m.setDefaultButton(m.buttons()[-1])
            m.exec()
            if m.clickedButton() is not keep:
                dl.cancel()
                self.toast(f"Blocked download from {host} ({threat})")
                return
        elif risky:
            insecure = dl.url().scheme() == "http"
            m = QMessageBox(self)
            m.setIcon(QMessageBox.Icon.Warning)
            m.setWindowTitle("Keep this file?")
            m.setText(f"<b>{escape(name)}</b> is an executable or script that can run code on your computer.")
            m.setInformativeText(f"Source: {escape(host or url)}"
                                 + ("<br><b>Served over plain HTTP — it could be tampered with in transit.</b>" if insecure else "")
                                 + "<br><br>Only keep it if you trust the source. You can verify it on VirusTotal after.")
            keep = m.addButton("Keep", QMessageBox.ButtonRole.AcceptRole)
            m.addButton("Discard", QMessageBox.ButtonRole.RejectRole)
            m.exec()
            if m.clickedButton() is not keep:
                dl.cancel()
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
        m = QMessageBox(self)
        m.setIcon(QMessageBox.Icon.Information)
        m.setWindowTitle("Download finished")
        m.setText(f"<b>{escape(name)}</b> downloaded.")
        m.setInformativeText("It's an executable. Check its reputation on VirusTotal before running?")
        vt = m.addButton("Check on VirusTotal", QMessageBox.ButtonRole.AcceptRole)
        m.addButton("Not now", QMessageBox.ButtonRole.RejectRole)
        m.exec()
        if m.clickedButton() is vt:
            self.open_url(f"https://www.virustotal.com/gui/file/{digest}", new_tab=True)
