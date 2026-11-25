#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/downloads.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Downloads: dangerous-file guard, a downloads list/panel (toolbar button), and VirusTotal lookup."""
from __future__ import annotations

import os
import subprocess
import sys
from html import escape

from PySide6.QtCore import QPoint, QSize, Qt, QUrl
from PySide6.QtWidgets import (QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QProgressBar, QPushButton,
                               QScrollArea, QToolButton, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

from ..ui.common import make_icon
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


# files Wyrm can preview in a tab (Chromium's built-in PDF viewer / native image rendering)
PREVIEWABLE_EXTS = {".pdf", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".avif"}


def _is_previewable(path: str) -> bool:
    return os.path.splitext(path or "")[1].lower() in PREVIEWABLE_EXTS


def _preview_in_tab(win, path: str):
    """Open a downloaded PDF or image in a new Wyrm tab (built-in viewer), no external app needed."""
    if not (path and os.path.isfile(path)):
        win.toast("That file is no longer there — it may have been moved or deleted.", 6000)
        return
    win.open_url(QUrl.fromLocalFile(path).toString(), new_tab=True)


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
               "risky": risky, "digest": "", "dl": dl, "paused": False, "speed": 0.0}
        self.downloads.insert(0, rec)
        del self.downloads[40:]  # keep the list manageable
        try:
            dl.receivedBytesChanged.connect(lambda d=dl, r=rec: self._dl_progress(d, r))
            dl.totalBytesChanged.connect(lambda d=dl, r=rec: self._dl_progress(d, r))
        except AttributeError:
            pass
        try:
            dl.isPausedChanged.connect(lambda d=dl, r=rec: self._dl_progress(d, r))
        except AttributeError:
            pass
        dl.isFinishedChanged.connect(lambda d=dl, r=rec: self._download_finished(d, r))
        self._dl_progress(dl, rec)
        self.toast(f"Downloading {rec['name']}…", 3000)
        self._refresh_downloads()

    def _dl_progress(self, dl, rec):
        import time
        try:
            recv, total = dl.receivedBytes(), dl.totalBytes()
        except (AttributeError, RuntimeError):
            recv, total = rec.get("received", 0), rec.get("total", 0)
        now = time.monotonic()
        last_t, last_b = rec.get("_t"), rec.get("_b", 0)
        if last_t and now > last_t and recv >= last_b:   # smoothed download speed (bytes/sec)
            inst = (recv - last_b) / (now - last_t)
            rec["speed"] = 0.7 * rec["speed"] + 0.3 * inst if rec.get("speed") else inst
        rec["_t"], rec["_b"] = now, recv
        rec["received"], rec["total"] = recv, total
        try:
            rec["paused"] = dl.isPaused()
        except (AttributeError, RuntimeError):
            pass
        self._refresh_downloads()

    def _dl_pause_toggle(self, rec):
        dl = rec.get("dl")
        if dl is None:
            return
        try:
            dl.resume() if dl.isPaused() else dl.pause()
            rec["paused"] = dl.isPaused()
        except (AttributeError, RuntimeError):
            return
        self._refresh_downloads()

    def _dl_cancel(self, rec):
        dl = rec.get("dl")
        try:
            if dl is not None:
                dl.cancel()
        except (AttributeError, RuntimeError):
            pass
        rec["state"] = "canceled"
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
        self._record_history(rec)
        self._refresh_downloads()

    # ---------------------------------------------------------------- downloads panel + badge
    def _init_downloads(self):
        if not hasattr(self, "downloads"):
            self.downloads: list = []
            self._downloads_popup = None

    def show_downloads(self):
        import time
        self._init_downloads()
        if self._downloads_popup is None:
            self._downloads_popup = DownloadsPopup(self)
        pop = self._downloads_popup
        # Toggle: close it if it's open. Clicking the button first deactivates the popup (changeEvent hides it
        # and stamps _dl_hidden_at), then fires this handler — so "just hidden" also counts as a toggle-close,
        # otherwise the same click would hide then instantly re-open it.
        just_hidden = (time.monotonic() - getattr(self, "_dl_hidden_at", 0.0)) < 0.25
        if pop.isVisible() or just_hidden:
            self._dl_hidden_at = 0.0
            pop.hide()
            return
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

    # ---------------------------------------------------------------- full download history (persisted)
    def _dl_history_file(self):
        return self.data_dir / "downloads.json"

    def _record_history(self, rec):
        """Append a finished download to the persisted history (skipped in private/Tor windows)."""
        if getattr(self, "ephemeral", False):
            return
        import json
        import time
        f = self._dl_history_file()
        hist = self.download_history()
        hist.insert(0, {"name": rec.get("name", ""), "path": rec.get("path", ""), "url": rec.get("url", ""),
                        "state": rec.get("state", ""), "size": rec.get("received") or rec.get("total") or 0,
                        "time": time.strftime("%Y-%m-%d %H:%M")})
        del hist[500:]
        try:
            from ..fileperms import write_text
            write_text(f, json.dumps(hist))   # 0600 (B5)
        except OSError:
            pass

    def download_history(self) -> list:
        import json
        try:
            h = json.loads(self._dl_history_file().read_text(encoding="utf-8"))
            return h if isinstance(h, list) else []
        except (OSError, ValueError):
            return []

    def clear_download_history(self):
        try:
            self._dl_history_file().unlink(missing_ok=True)
        except OSError:
            pass

    def show_download_history(self):
        if getattr(self, "_dl_history_win", None) is None:
            self._dl_history_win = DownloadsHistoryWindow(self)
        w = self._dl_history_win
        w.reload()
        w.show()
        w.raise_()
        w.activateWindow()

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
            self._downloads_popup.sync()

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


def _fmt_eta(seconds) -> str:
    s = int(seconds)
    if s < 60:
        return f"{s}s"
    if s < 3600:
        return f"{s // 60}m {s % 60}s"
    return f"{s // 3600}h {(s % 3600) // 60}m"


class DownloadsHistoryWindow(QWidget):
    """A full, searchable download history (persisted across sessions) — opened from the downloads popup."""

    def __init__(self, win):
        super().__init__()
        self.win = win
        self.setWindowTitle("Download history — Wyrm")
        self.resize(760, 480)
        v = QVBoxLayout(self)
        top = QHBoxLayout()
        top.addWidget(QLabel("<b>Download history</b>"), 0)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search downloads…")
        self.search.textChanged.connect(self._filter)
        top.addWidget(self.search, 1)
        clear = QPushButton("Clear history")
        clear.clicked.connect(self._clear)
        top.addWidget(clear)
        v.addLayout(top)

        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Name", "Size", "Status", "When", "Folder"])
        self.tree.setRootIsDecorated(False)
        self.tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.tree.itemDoubleClicked.connect(self._open_item)
        v.addWidget(self.tree, 1)

        row = QHBoxLayout()
        row.addStretch(1)
        b_prev = QPushButton("Preview")
        b_prev.setToolTip("Open a PDF or image in a Wyrm tab")
        b_prev.clicked.connect(self._preview)
        row.addWidget(b_prev)
        b_open = QPushButton("Open")
        b_open.clicked.connect(lambda: self._open_item(self.tree.currentItem()))
        row.addWidget(b_open)
        b_folder = QPushButton("Show in folder")
        b_folder.clicked.connect(self._show_in_folder)
        row.addWidget(b_folder)
        v.addLayout(row)

    def _preview(self):
        it = self.tree.currentItem()
        rec = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not rec:
            return
        if _is_previewable(rec.get("path", "")):
            _preview_in_tab(self.win, rec["path"])
        else:
            self.win.toast("Preview supports PDFs and images. Use Open for other files.", 5000)

    def reload(self):
        self.tree.clear()
        from PySide6.QtGui import QBrush, QColor
        for rec in self.win.download_history():
            folder = os.path.dirname(rec.get("path", ""))
            gone = not (rec.get("path") and os.path.isfile(rec["path"]))
            state = "deleted" if gone else rec.get("state", "")
            it = QTreeWidgetItem([rec.get("name", ""), _fmt_size(rec.get("size", 0)),
                                  state, rec.get("time", ""), folder])
            it.setData(0, Qt.ItemDataRole.UserRole, rec)
            if gone:   # file no longer on disk → grey it out and make it non-selectable (can't Preview/Open)
                it.setFlags(it.flags() & ~Qt.ItemFlag.ItemIsEnabled)
                for c in range(5):
                    it.setForeground(c, QBrush(QColor("#9aa3ad")))
            self.tree.addTopLevelItem(it)
        if not self.tree.topLevelItemCount():
            self.tree.addTopLevelItem(QTreeWidgetItem(["No downloads yet.", "", "", "", ""]))
        self._filter()

    def _filter(self):
        q = self.search.text().strip().lower()
        for i in range(self.tree.topLevelItemCount()):
            it = self.tree.topLevelItem(i)
            hay = " ".join(it.text(c) for c in range(5)).lower()
            it.setHidden(bool(q) and q not in hay)

    def _open_item(self, it):
        rec = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if not rec:
            return
        p = rec.get("path", "")
        if p and os.path.isfile(p):
            _open_path(p)
        else:
            self.win.toast("That file is no longer there — it may have been moved or deleted.", 6000)

    def _show_in_folder(self):
        it = self.tree.currentItem()
        rec = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if rec and rec.get("path"):
            _show_in_folder(rec["path"])

    def _clear(self):
        self.win.clear_download_history()
        self.reload()


def _dl_status_text(rec) -> str:
    """The subtitle under an active download: size, state, speed and ETA (like other browsers)."""
    recv, total = rec.get("received") or 0, rec.get("total") or 0
    size = f"{_fmt_size(recv)} of {_fmt_size(total)}" if total > 0 else _fmt_size(recv)
    if rec.get("paused"):
        return f"{size} · Paused"
    speed = rec.get("speed") or 0
    parts = [size, "Downloading…"]
    if speed > 0:
        parts.append(f"{_fmt_size(speed)}/s")
        if total > recv:
            parts.append(f"{_fmt_eta((total - recv) / speed)} left")
    return " · ".join(parts)


class DownloadsPopup(QWidget):
    """A frameless panel under the Downloads button listing recent downloads with Open / Show in folder."""

    def __init__(self, win):
        super().__init__(win, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint)
        self.win = win
        self._rows: dict = {}     # id(rec) -> {bar, sub, pause} for live in-place updates (no flicker)
        self._sig = None          # membership/state signature: rebuild only when it changes
        self.setObjectName("DownloadsPopup")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground)
        self.resize(400, 420)
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        head = QHBoxLayout()
        head.setContentsMargins(14, 10, 10, 6)
        title = QLabel("<b>Recent downloads</b>")
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

        foot = QHBoxLayout()
        foot.setContentsMargins(14, 6, 12, 10)
        full = QPushButton("Full download history  →")
        full.setObjectName("Link")
        full.setCursor(Qt.CursorShape.PointingHandCursor)
        full.setFlat(True)
        full.clicked.connect(self._open_full_history)
        foot.addWidget(full)
        foot.addStretch(1)
        outer.addLayout(foot)

    def _open_full_history(self):
        self.hide()
        self.win.show_download_history()

    def _clear(self):
        self.win.downloads = [r for r in self.win.downloads if r["state"] == "active"]
        self.rebuild()
        self.win._refresh_downloads()

    def sync(self):
        """Rebuild only when the set of downloads (or their states) changes; otherwise update progress in place
        so the bars/speed animate smoothly without flicker or losing button hover."""
        sig = tuple((id(r), r["state"]) for r in self.win.downloads)
        if sig != self._sig:
            self._sig = sig
            self.rebuild()
        else:
            self.update_progress()

    def update_progress(self):
        for rec in self.win.downloads:
            if rec["state"] != "active":
                continue
            refs = self._rows.get(id(rec))
            if not refs:
                continue
            self._apply_progress(rec, refs)

    def _apply_progress(self, rec, refs):
        bar = refs["bar"]
        total, recv = rec.get("total") or 0, rec.get("received") or 0
        if total > 0:
            if bar.maximum() == 0:
                bar.setRange(0, 100)
            bar.setValue(int(recv * 100 / total))
        else:
            bar.setRange(0, 0)   # unknown size: busy indicator
        refs["sub"].setText(_dl_status_text(rec))
        if refs.get("pause") is not None:
            refs["pause"].setIcon(make_icon("play" if rec.get("paused") else "pause", self._icon_col, 32))
            refs["pause"].setToolTip("Resume" if rec.get("paused") else "Pause")

    def rebuild(self):
        while self.vbox.count() > 1:
            it = self.vbox.takeAt(0)
            w = it.widget()
            if w:
                w.deleteLater()
        self._rows = {}
        self._icon_col = self.palette().text().color().name()   # theme-adaptive icon color
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
            sub = QLabel()
            sub.setObjectName("Muted")
            v.addWidget(sub)
            prow = QHBoxLayout()
            prow.setSpacing(6)
            bar = QProgressBar()
            bar.setTextVisible(False)
            bar.setFixedHeight(8)
            prow.addWidget(bar, 1)
            refs = {"bar": bar, "sub": sub, "pause": None}
            if hasattr(rec.get("dl"), "pause"):   # pause/resume (Qt 6.5+)
                pbtn = QToolButton()
                pbtn.setAutoRaise(True)
                pbtn.setIconSize(QSize(16, 16))
                pbtn.setCursor(Qt.CursorShape.PointingHandCursor)
                pbtn.setToolTip("Pause")
                pbtn.clicked.connect(lambda _c=False, r=rec: self.win._dl_pause_toggle(r))
                prow.addWidget(pbtn)
                refs["pause"] = pbtn
            cbtn = QToolButton()
            cbtn.setAutoRaise(True)
            cbtn.setIconSize(QSize(16, 16))
            cbtn.setIcon(make_icon("win_close", self._icon_col, 32))
            cbtn.setCursor(Qt.CursorShape.PointingHandCursor)
            cbtn.setToolTip("Cancel")
            cbtn.clicked.connect(lambda _c=False, r=rec: self.win._dl_cancel(r))
            prow.addWidget(cbtn)
            v.addLayout(prow)
            self._rows[id(rec)] = refs
            self._apply_progress(rec, refs)
        else:
            row = QHBoxLayout()
            row.setSpacing(6)
            exists = rec["state"] == "done" and os.path.isfile(rec["path"])
            if rec["state"] == "done" and exists:
                status = QLabel(f"<span style='color:#3fb950'>Done</span> · {escape(os.path.dirname(rec['path']))}")
            elif rec["state"] == "done":   # file was deleted/moved: grey it out, like other browsers
                status = QLabel("<span style='color:#9aa3ad'>Deleted — no longer on disk</span>")
                name.setEnabled(False)
            elif rec["state"] == "canceled":
                status = QLabel("<span style='color:#9aa3ad'>Canceled</span>")
            else:
                status = QLabel(f"<span style='color:#ff5c5c'>Failed</span> · {escape(rec.get('error', ''))}")
            status.setObjectName("Muted")
            status.setWordWrap(True)
            v.addWidget(status)
            if rec["state"] == "done":
                actions = []
                if _is_previewable(rec["path"]):
                    actions.append(("Preview", lambda _c=False, p=rec["path"]: _preview_in_tab(self.win, p)))
                actions += [("Open", lambda _c=False, p=rec["path"]: self._open(p)),
                            ("Show in folder", lambda _c=False, p=rec["path"]: _show_in_folder(p))]
                for label, fn in actions:
                    b = QPushButton(label)
                    b.setEnabled(exists)   # deleted file → greyed, not clickable (like other browsers)
                    if exists:
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
            import time
            self.win._dl_hidden_at = time.monotonic()   # so a click on the Downloads button toggles (not re-opens)
            self.hide()
