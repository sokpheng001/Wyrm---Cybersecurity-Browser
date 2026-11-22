#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/downloads.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Downloads: dangerous-file guard, a downloads list/panel (toolbar button), and VirusTotal lookup."""
from __future__ import annotations

import os
import subprocess
import sys
from html import escape

from PySide6.QtCore import QPoint, Qt
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QLabel, QProgressBar, QPushButton, QScrollArea, QVBoxLayout,
                               QWidget)

from ..ui.dialogs import security_warning


def _open_path(path):
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa: S606 - the user asked to open their own download
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
        return True
    except OSError:
        return False


def _show_in_folder(path):
    try:
        if sys.platform == "win32":
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", "-R", path])
        else:
            subprocess.Popen(["xdg-open", os.path.dirname(path)])
    except OSError:
        pass


class DownloadsMixin:
    """Downloads: dangerous-file guard, downloads panel, VirusTotal lookup. (Mixed into MainWindow.)"""

    # ================================================================ downloads / lifecycle
    RISKY_EXT = {".exe", ".msi", ".msix", ".msp", ".appx", ".bat", ".cmd", ".com", ".scr", ".pif", ".ps1", ".psm1",
                 ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".jar", ".hta", ".cpl", ".dll", ".sys", ".apk",
                 ".dmg", ".pkg", ".app", ".deb", ".rpm", ".appimage", ".sh", ".run", ".bin", ".reg", ".lnk", ".url",
                 ".iso", ".img", ".vhd", ".vhdx", ".crx", ".xpi",
                 ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".xlam", ".ppam"}   # Office files with macros

    def _on_download(self, dl):
        self._init_downloads()
        from pathlib import PurePosixPath
        url = dl.url().toString()
        name = dl.downloadFileName()
        host = dl.url().host()
        ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else \
              ("." + PurePosixPath(dl.url().path()).suffix.lstrip(".").lower() if PurePosixPath(dl.url().path()).suffix else "")
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
            or _default_download_dir()
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
            os.makedirs(folder, exist_ok=True)
            dl.setDownloadDirectory(folder)
            dl.setDownloadFileName(name)
        except Exception:  # noqa: BLE001 - older Qt
            pass
        dl.accept()
        rec = {"name": dl.downloadFileName() or name, "path": os.path.join(dl.downloadDirectory() or folder,
               dl.downloadFileName() or name), "url": url, "state": "active", "received": 0, "total": 0,
               "risky": risky, "digest": ""}
        self.downloads.insert(0, rec)
        del self.downloads[40:]  # keep the list manageable
        try:
            dl.receivedBytesChanged.connect(lambda d=dl, r=rec: self._dl_progress(d, r))
            dl.totalBytesChanged.connect(lambda d=dl, r=rec: self._dl_progress(d, r))
        except AttributeError:
            pass
        dl.isFinishedChanged.connect(lambda d=dl, r=rec: self._download_finished(d, r))
        self._dl_progress(dl, rec)
        self.toast(f"Downloading {rec['name']}…", 3000)
        self._refresh_downloads()

    def _dl_progress(self, dl, rec):
        try:
            rec["received"], rec["total"] = dl.receivedBytes(), dl.totalBytes()
        except (AttributeError, RuntimeError):
            pass
        self._refresh_downloads()

    def _download_finished(self, dl, rec):
        from PySide6.QtWebEngineCore import QWebEngineDownloadRequest as DR
        state = dl.state()
        rec["path"] = os.path.join(dl.downloadDirectory(), dl.downloadFileName())  # real path (handles renames)
        rec["name"] = dl.downloadFileName()
        if state == DR.DownloadState.DownloadCompleted:
            rec["state"] = "done"
            self.toast(f"Downloaded {rec['name']}", 6000)
            if rec["risky"]:  # compute the SHA-256 for an optional VirusTotal check (no upload)
                self.runner.run(lambda p=rec["path"]: self._sha256(p),
                                lambda ok, h: (rec.__setitem__("digest", h), self._refresh_downloads()) if ok else None)
            self.show_downloads()  # surface it so the file is easy to find and open
        elif state == DR.DownloadState.DownloadCancelled:
            rec["state"] = "canceled"
        else:
            rec["state"] = "failed"
            rec["error"] = dl.interruptReasonString() if hasattr(dl, "interruptReasonString") else "interrupted"
            self.toast(f"Download failed: {rec['name']}", 8000)
        self._refresh_downloads()

    # ---------------------------------------------------------------- downloads panel + badge
    def _init_downloads(self):
        if not hasattr(self, "downloads"):
            self.downloads: list = []
            self._downloads_popup = None

    def show_downloads(self):
        self._init_downloads()
        if self._downloads_popup is None:
            self._downloads_popup = DownloadsPopup(self)
        pop = self._downloads_popup
        pop.rebuild()
        anchor = getattr(self, "b_downloads", None)
        if anchor is not None and anchor.isVisible():
            tr = anchor.mapToGlobal(QPoint(anchor.width(), anchor.height() + 4))
            pop.move(tr.x() - pop.width(), tr.y())
        else:
            pop.move(self.mapToGlobal(QPoint(self.width() - pop.width() - 16, 96)))
        pop.show()
        pop.raise_()
        pop.activateWindow()
        self._refresh_downloads()

    def _refresh_downloads(self):
        self._init_downloads()
        active = sum(1 for r in self.downloads if r["state"] == "active")
        badge = getattr(self, "dl_badge", None)
        if badge is not None:
            badge.setText(str(active))
            badge.adjustSize()
            bw = max(16, badge.width())
            badge.setGeometry(40 - bw - 1, 2, bw, 16)
            badge.setVisible(active > 0)
        if self._downloads_popup is not None and self._downloads_popup.isVisible():
            self._downloads_popup.rebuild()

    # kept for callers / tests
    @staticmethod
    def _open_file(path):
        return _open_path(path)

    @staticmethod
    def _show_in_folder(path):
        _show_in_folder(path)

    @staticmethod
    def _sha256(path):
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()


def _default_download_dir():
    from PySide6.QtCore import QStandardPaths
    return QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DownloadLocation)


def _fmt_size(n) -> str:
    n = float(n or 0)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


class DownloadsPopup(QWidget):
    """A frameless panel under the Downloads button listing recent downloads with Open / Show in folder."""

    def __init__(self, win):
        super().__init__(win, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint)
        self.win = win
        self.setObjectName("DownloadsPopup")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.resize(400, 420)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        head.setContentsMargins(14, 10, 10, 6)
        title = QLabel("<b>Downloads</b>")
        head.addWidget(title, 1)
        clear = QPushButton("Clear")
        clear.setCursor(Qt.CursorShape.PointingHandCursor)
        clear.clicked.connect(self._clear)
        head.addWidget(clear)
        outer.addLayout(head)
        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        outer.addWidget(self.scroll, 1)
        self.body = QWidget()
        self.vbox = QVBoxLayout(self.body)
        self.vbox.setContentsMargins(8, 4, 8, 8)
        self.vbox.setSpacing(6)
        self.vbox.addStretch(1)
        self.scroll.setWidget(self.body)

    def _clear(self):
        self.win.downloads = [r for r in self.win.downloads if r["state"] == "active"]
        self.rebuild()
        self.win._refresh_downloads()

    def rebuild(self):
        while self.vbox.count() > 1:
            it = self.vbox.takeAt(0)
            w = it.widget()
            if w:
                w.deleteLater()
        if not self.win.downloads:
            empty = QLabel("No downloads yet.")
            empty.setObjectName("Muted")
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.vbox.insertWidget(0, empty)
            return
        for rec in self.win.downloads:
            self.vbox.insertWidget(self.vbox.count() - 1, self._row(rec))

    def _row(self, rec):
        card = QFrame()
        card.setObjectName("DlRow")
        v = QVBoxLayout(card)
        v.setContentsMargins(10, 8, 10, 8)
        v.setSpacing(4)
        name = QLabel(escape(rec["name"]))
        name.setObjectName("DlName")
        name.setWordWrap(True)
        v.addWidget(name)
        if rec["state"] == "active":
            bar = QProgressBar()
            total, recv = rec.get("total") or 0, rec.get("received") or 0
            if total > 0:
                bar.setMaximum(100)
                bar.setValue(int(recv * 100 / total))
                bar.setFormat(f"{_fmt_size(recv)} / {_fmt_size(total)}")
            else:
                bar.setRange(0, 0)  # unknown size: busy indicator
                bar.setFormat(_fmt_size(recv))
            v.addWidget(bar)
        else:
            row = QHBoxLayout()
            row.setSpacing(6)
            if rec["state"] == "done":
                status = QLabel(f"<span style='color:#3fb950'>Done</span> · {escape(os.path.dirname(rec['path']))}")
            elif rec["state"] == "canceled":
                status = QLabel("<span style='color:#9aa3ad'>Canceled</span>")
            else:
                status = QLabel(f"<span style='color:#ff5c5c'>Failed</span> · {escape(rec.get('error', ''))}")
            status.setObjectName("Muted")
            status.setWordWrap(True)
            v.addWidget(status)
            if rec["state"] == "done":
                for label, fn in (("Open", lambda _c=False, p=rec["path"]: self._open(p)),
                                  ("Show in folder", lambda _c=False, p=rec["path"]: _show_in_folder(p))):
                    b = QPushButton(label)
                    b.setCursor(Qt.CursorShape.PointingHandCursor)
                    b.clicked.connect(fn)
                    row.addWidget(b)
                if rec.get("risky") and rec.get("digest"):
                    vt = QPushButton("Scan (VirusTotal)")
                    vt.setCursor(Qt.CursorShape.PointingHandCursor)
                    vt.clicked.connect(lambda _c=False, d=rec["digest"]:
                                       self.win.open_url(f"https://www.virustotal.com/gui/file/{d}", new_tab=True))
                    row.addWidget(vt)
            row.addStretch(1)
            v.addLayout(row)
        return card

    def _open(self, path):
        if not (path and os.path.isfile(path)):
            self.win.toast("That file is no longer there — it may have been moved or deleted.", 6000)
            return
        if not _open_path(path):
            self.win.toast("Couldn't open the file. Use “Show in folder” to find it.", 6000)

    def changeEvent(self, e):
        super().changeEvent(e)
        from PySide6.QtCore import QEvent
        if e.type() == QEvent.Type.ActivationChange and not self.isActiveWindow():
            self.hide()
