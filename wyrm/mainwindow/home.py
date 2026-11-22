#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/home.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Start page: news, CISA KEV feed, backgrounds (Customize) and wyrm:// actions."""
from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QTimer
from PySide6.QtGui import QImageReader
from PySide6.QtWebEngineCore import QWebEnginePage
from PySide6.QtWidgets import QFileDialog, QMessageBox

from .. import engines, pages
from ..security import news as news_mod


class HomeMixin:
    """Start page: news, CISA KEV feed, backgrounds (Customize) and wyrm:// actions. (Mixed into MainWindow.)"""

    def _kev_ready(self, ok, result):
        if ok and result:
            self._kev_recent = result
            self._refresh_home_pages()

    def _refresh_home_pages(self):
        for i in range(self.tabbar.count()):  # reload open start pages so new feeds / background show up
            v = self.tabbar.tabData(i)
            u = v.url()
            if u.scheme() == "wyrm" and u.host() in ("home", ""):
                v.page().triggerAction(QWebEnginePage.WebAction.ReloadAndBypassCache)

    # ---------------------------------------------------------------- start page: news + background
    def _fetch_news(self):
        if self.tor or not self._is_online:
            return
        self.runner.run(lambda: news_mod.latest(8, self.proxies(), self.verify_tls()), self._news_ready)

    def _news_ready(self, ok, result):
        if ok and result and result != self._news:
            self._news = result
            self._refresh_home_pages()

    BG_DIR = "backgrounds"

    BG_EXTS = {".jpg": b"image/jpeg", ".jpeg": b"image/jpeg", ".png": b"image/png", ".webp": b"image/webp",
               ".gif": b"image/gif"}

    BG_MAX_BYTES = 25 * 1024 * 1024

    def _custom_bg_path(self) -> Path | None:
        d = self.data_dir / self.BG_DIR
        return next((f for f in sorted(d.glob("custom.*")) if f.suffix.lower() in self.BG_EXTS), None) \
            if d.is_dir() else None

    def _custom_bg(self):
        f = self._custom_bg_path()
        try:
            return (f.read_bytes(), self.BG_EXTS[f.suffix.lower()]) if f else None
        except OSError:
            return None

    def _bg_settings(self) -> dict:
        s = self.settings
        mode = s.value("home/bg_mode", "", type=str)
        if mode not in ("random", "color", "image", "none"):  # older versions: a single on/off switch
            mode = "random" if s.value("home/background", True, type=bool) else "none"
        f = self._custom_bg_path()
        ver = str(int(f.stat().st_mtime)) if f else ""
        if mode == "image" and not ver:
            mode = "random"
        return {"mode": mode, "color": s.value("home/bg_color", "midnight", type=str), "image_ver": ver,
                "interval": self._bg_interval()}

    def _bg_interval(self) -> int:
        """Minutes between wallpaper changes (Customize → Change wallpaper every); also applied to pages."""
        mins = self.settings.value("home/bg_interval_min", 30, type=int)
        if mins not in pages.BG_INTERVAL_LABEL:
            mins = 30
        pages.BG_ROTATE_MS = mins * 60 * 1000  # read by the start page timer and the wyrm://bg cache
        return mins

    def _set_background(self, params: dict):
        mode = params.get("mode", "")
        if mode not in ("random", "color", "image", "none"):
            return
        if mode == "color":
            color = params.get("color", "")
            if color not in pages.BG_COLOR_CSS:
                return
            self.settings.setValue("home/bg_color", color)
        self.settings.setValue("home/bg_mode", mode)
        self.settings.setValue("home/background", mode != "none")
        self.settings.sync()
        QTimer.singleShot(0, self._refresh_home_pages)

    def _pick_background_image(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a background image", str(Path.home() / "Pictures"),
                                              "Images (*.jpg *.jpeg *.png *.webp *.gif)")
        if not path:
            return
        src = Path(path)
        ext = src.suffix.lower()
        try:
            size = src.stat().st_size
        except OSError:
            return
        reader = QImageReader(str(src))
        if ext not in self.BG_EXTS or size > self.BG_MAX_BYTES or not reader.canRead():
            QMessageBox.warning(self, "Background", "Please choose a JPG, PNG, WebP or GIF image up to 25 MB.")
            return
        d = self.data_dir / self.BG_DIR
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("custom.*"):
            old.unlink(missing_ok=True)
        (d / f"custom{ext}").write_bytes(src.read_bytes())
        self._set_background({"mode": "image"})

    def scheme_action(self, action: str, params: dict) -> str | None:
        """Called by wyrm://allow and wyrm://do links. Returns a URL to continue to (or None)."""
        if action.startswith("do:"):
            do = action[3:]
            if do == "tor":
                self.open_tor_window()
            elif do == "scan":
                self.security.show_tab("Overview")
                QTimer.singleShot(50, self.security.overview.analyze_current)
            elif do == "recon":
                self.security.show_tab("Recon")
                QTimer.singleShot(50, self.security.recon.use_current)
            elif do == "bg" and not self.tor:
                self._set_background(params)
            elif do == "bg-interval" and not self.tor:
                try:
                    mins = int(params.get("min", ""))
                except ValueError:
                    mins = 0
                if mins in pages.BG_INTERVAL_LABEL:
                    self.settings.setValue("home/bg_interval_min", mins)
                    self._bg_interval()
                    QTimer.singleShot(0, self._refresh_home_pages)
            elif do == "hist-del" and self.history_db is not None:
                try:
                    self.history_db.delete(int(params.get("id", "0")))
                except ValueError:
                    pass
            elif do == "hist-clear" and self.history_db is not None:
                self.history_db.clear()
                self.toast("Browsing history cleared")
            elif do == "bg-upload" and not self.tor:
                QTimer.singleShot(0, self._pick_background_image)  # don't block the scheme request on a dialog
            return None
        host, url = params.get("host", ""), params.get("url", "")
        if action == "allow-threat" and host:
            self.shields.malware_allow.add(host)
        elif action == "allow-http" and host:
            self.http_allowed.add(host)
            url = "http://" + url.split("://", 1)[-1]
        return url or None

    def home_context(self) -> dict:
        e = self.engagement
        eng = {"name": e.name, "scope": e.scope, "block": e.block_out_of_scope} if e else None
        name = engines.ENGINES.get(self.default_engine(), engines.ENGINES[engines.DEFAULT_ENGINE]).name
        return {"engagement": eng, "counts": self.store.counts(e.id) if e else {}, "engine_name": name,
                "saved": self.library.saved(), "kev": self._kev_recent, "mode": self.mode,
                "background": (not self.tor) and self._bg_settings()["mode"] != "none",
                "bg": self._bg_settings(), "news": self._news if self._is_online else [],
                "weather": getattr(self, "_weather", None) if self._is_online else None,
                "tor": bool(self.tor), "private": self.private}

    def _fetch_weather(self):
        # location + weather for the start page; off in private/Tor and when the user disables it
        if self.ephemeral or not self._is_online \
                or not self.settings.value("home/weather", True, type=bool):
            return
        from .. import homeinfo
        self.runner.run(lambda: homeinfo.fetch(self.proxies(), self.verify_tls()), self._weather_ready)

    def _weather_ready(self, ok, result):
        if ok and result and result != getattr(self, "_weather", None):
            self._weather = result
            self._refresh_home_pages()
