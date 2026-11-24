#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/home.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
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
        # Try even when reachability reports offline — that backend misreports on some systems (e.g. macOS),
        # which was leaving the start page with no news. A real offline machine just fails quietly and cheaply.
        if self.tor:
            return
        self.runner.run(lambda: news_mod.latest(8, self.proxies(), self.verify_tls()), self._news_ready)

    def _news_ready(self, ok, result):
        if ok and result:
            if not self._is_online:   # we clearly reached the internet: correct a false "offline" state
                self._is_online = True
                banner = getattr(self, "offline_banner", None)
                if banner is not None:
                    banner.set_offline(False)
            if result != self._news:
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

    VIDEO_EXTS = {".mp4": b"video/mp4", ".webm": b"video/webm", ".m4v": b"video/mp4", ".mov": b"video/quicktime"}
    VIDEO_MAX_BYTES = 60 * 1024 * 1024

    def _custom_video_path(self) -> "Path | None":
        d = self.data_dir / self.BG_DIR
        return next((f for f in sorted(d.glob("customvid.*")) if f.suffix.lower() in self.VIDEO_EXTS), None) \
            if d.is_dir() else None

    def _custom_video(self):
        f = self._custom_video_path()
        return (f.read_bytes(), self.VIDEO_EXTS[f.suffix.lower()]) if f else None

    def _bg_settings(self) -> dict:
        s = self.settings
        mode = s.value("home/bg_mode", "", type=str)
        if mode not in ("random", "color", "image", "animated", "video_local", "weather", "none"):
            mode = "random" if s.value("home/background", True, type=bool) else "none"
        f = self._custom_bg_path()
        ver = str(int(f.stat().st_mtime)) if f else ""
        vf = self._custom_video_path()
        vver = str(int(vf.stat().st_mtime)) if vf else ""
        if mode == "image" and not ver:
            mode = "random"
        if mode == "video" and vver:        # legacy "video" (bundled) → the user's uploaded video or animated
            mode = "video_local"
        elif mode == "video":
            mode = "animated"
        if mode == "video_local" and not vver:
            mode = "animated"
        return {"mode": mode, "color": s.value("home/bg_color", "midnight", type=str), "image_ver": ver,
                "video_ver": vver, "anim": s.value("home/anim", "aurora", type=str),
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
        if mode not in ("random", "color", "image", "animated", "video_local", "weather", "none"):
            return
        if mode == "color":
            color = params.get("color", "")
            if color not in pages.BG_COLOR_CSS:
                return
            self.settings.setValue("home/bg_color", color)
        if mode == "animated":
            anim = params.get("anim", "")
            if anim in pages.ANIM_SCENES:
                self.settings.setValue("home/anim", anim)
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

    def _pick_background_video(self):
        path, _ = QFileDialog.getOpenFileName(self, "Choose a background video", str(Path.home() / "Videos"),
                                              "Videos (*.mp4 *.webm *.m4v *.mov)")
        if not path:
            return
        src = Path(path)
        ext = src.suffix.lower()
        try:
            size = src.stat().st_size
        except OSError:
            return
        if ext not in self.VIDEO_EXTS or size > self.VIDEO_MAX_BYTES:
            QMessageBox.warning(self, "Background", "Please choose an MP4 or WebM video up to 60 MB.")
            return
        d = self.data_dir / self.BG_DIR
        d.mkdir(parents=True, exist_ok=True)
        for old in d.glob("customvid.*"):
            old.unlink(missing_ok=True)
        (d / f"customvid{ext}").write_bytes(src.read_bytes())
        self._set_background({"mode": "video_local"})

    def _remove_background_image(self):
        d = self.data_dir / self.BG_DIR
        if d.is_dir():
            for f in d.glob("custom.*"):
                f.unlink(missing_ok=True)
        if self.settings.value("home/bg_mode", "", type=str) == "image":  # was active → back to Wyrm wallpapers
            self._set_background({"mode": "random"})
        else:
            QTimer.singleShot(0, self._refresh_home_pages)
        self.toast("Removed your uploaded image")

    def _remove_background_video(self):
        d = self.data_dir / self.BG_DIR
        if d.is_dir():
            for f in d.glob("customvid.*"):
                f.unlink(missing_ok=True)
        if self.settings.value("home/bg_mode", "", type=str) == "video_local":
            self._set_background({"mode": "random"})
        else:
            QTimer.singleShot(0, self._refresh_home_pages)
        self.toast("Removed your uploaded video")

    # ---------------------------------------------------------------- start-page shortcuts (speed dial)
    DEFAULT_SHORTCUTS = [
        {"title": "HackerOne", "url": "https://hackerone.com"},
        {"title": "Exploit-DB", "url": "https://www.exploit-db.com"},
        {"title": "MITRE ATT&CK", "url": "https://attack.mitre.org"},
        {"title": "CVE", "url": "https://www.cve.org"},
        {"title": "OWASP", "url": "https://owasp.org"},
    ]

    def _shortcuts(self) -> list:
        import json
        raw = self.settings.value("home/shortcuts", None)
        if raw is None:                       # first run: seed a useful starter set the user can edit
            return [dict(s) for s in self.DEFAULT_SHORTCUTS]
        try:
            v = json.loads(raw) if isinstance(raw, str) else raw
        except (ValueError, TypeError):
            return []
        if not isinstance(v, list):
            return []
        # an entry is a link {url,title} or a folder {title, items:[...]}
        return [s for s in v if isinstance(s, dict) and (s.get("url") or isinstance(s.get("items"), list))]

    def _save_shortcuts(self, lst: list, refresh_page: bool = True):
        import json
        self.settings.setValue("home/shortcuts", json.dumps(lst))
        self.settings.sync()
        if refresh_page:   # deletes skip this so the start page doesn't visibly reload
            QTimer.singleShot(0, self._refresh_home_pages)
        QTimer.singleShot(0, self._fetch_shortcut_icons)  # grab favicons for any new shortcuts
        if hasattr(self, "_refresh_bookmarks_bar"):
            QTimer.singleShot(0, self._refresh_bookmarks_bar)

    def _shortcuts_with_icons(self) -> list:
        from .. import pages
        out = []
        for s in self._shortcuts():
            if isinstance(s.get("items"), list):   # folder
                items = [{**it, "icon": self._shortcut_icon(pages._sc_domain(it.get("url", "")))}
                         for it in s["items"] if it.get("url")]
                out.append({"title": s.get("title", ""), "items": items, "is_folder": True})
            else:
                out.append({**s, "icon": self._shortcut_icon(pages._sc_domain(s.get("url", "")))})
        return out

    def _shortcut_icon_dir(self):
        return self.data_dir / "shortcut_icons"

    def _shortcut_icon(self, dom: str) -> str:
        """A data: URI for a cached shortcut favicon, or '' if we don't have one yet."""
        import base64
        p = self._shortcut_icon_dir() / (dom + ".img")
        try:
            b = p.read_bytes()
        except OSError:
            return ""
        sig = b[:4]
        mime = ("image/png" if sig.startswith(b"\x89PNG") else "image/gif" if sig[:3] == b"GIF"
                else "image/jpeg" if sig[:2] == b"\xff\xd8" else "image/svg+xml" if b[:5] == b"<?xml" or b[:4] == b"<svg"
                else "image/x-icon")
        return f"data:{mime};base64," + base64.b64encode(b).decode()

    def _fetch_shortcut_icons(self):
        """Download favicons for shortcuts we don't have yet, in the background, then refresh the start page."""
        if self.ephemeral:
            return
        from .. import homeinfo, pages
        want, seen = [], set()

        def consider(url):
            dom = pages._sc_domain(url or "")
            if dom and dom not in seen and not (self._shortcut_icon_dir() / (dom + ".img")).exists():
                seen.add(dom)
                want.append((dom, url))
        for s in self._shortcuts():
            if isinstance(s.get("items"), list):
                for it in s["items"]:
                    consider(it.get("url", ""))
            else:
                consider(s.get("url", ""))
        if not want:
            return
        px, verify = self.proxies(), self.verify_tls()

        def work():
            d = self._shortcut_icon_dir()
            d.mkdir(parents=True, exist_ok=True)
            got = 0
            for dom, url in want:
                data = homeinfo.fetch_favicon(dom, url, px, verify)
                if data:
                    (d / (dom + ".img")).write_bytes(data)
                    got += 1
            return got
        def done(ok, n):
            if ok and n:
                self._refresh_home_pages()
                if hasattr(self, "_refresh_bookmarks_bar"):
                    self._refresh_bookmarks_bar()   # show the new favicons on the bar too
        self.runner.run(work, done)

    def _add_shortcut(self):
        from PySide6.QtWidgets import QInputDialog
        from .. import pages
        url, ok = QInputDialog.getText(self, "Add shortcut", "Website address (e.g. example.com):")
        if not ok or not url.strip():
            return
        url = url.strip()
        if "://" not in url:
            url = "https://" + url
        title, ok = QInputDialog.getText(self, "Add shortcut", "Name:", text=pages._sc_domain(url))
        if not ok:
            return
        lst = self._shortcuts()
        lst.append({"title": title.strip() or pages._sc_domain(url), "url": url})
        self._save_shortcuts(lst)

    def _del_shortcut(self, i: int):
        lst = self._shortcuts()
        if 0 <= i < len(lst):
            lst.pop(i)
            self._save_shortcuts(lst, refresh_page=False)   # no visible page reload on delete

    def _del_shortcut_url(self, url: str):
        """Delete a top-level bookmark by URL (used by the start-page grid × so it stays correct without a
        reload — the tile is removed client-side)."""
        if not url:
            return
        lst = self._shortcuts()
        for j, s in enumerate(lst):
            if not isinstance(s.get("items"), list) and s.get("url") == url:
                lst.pop(j)
                self._save_shortcuts(lst, refresh_page=False)
                return

    def _rename_shortcut(self, i: int):
        from PySide6.QtWidgets import QInputDialog
        lst = self._shortcuts()
        if not (0 <= i < len(lst)):
            return
        s = lst[i]
        title, ok = QInputDialog.getText(self, "Rename", "Name:", text=s.get("title", ""))
        if not ok:
            return
        s["title"] = title.strip() or s.get("title", "")
        if "items" not in s:   # a bookmark (not a folder) — also let the address be edited
            url, ok = QInputDialog.getText(self, "Edit bookmark", "Address:", text=s.get("url", ""))
            if ok and url.strip():
                u = url.strip()
                s["url"] = u if "://" in u else "https://" + u
        self._save_shortcuts(lst, refresh_page=False)

    def _bookmark_current(self):
        """Ctrl+D — add the current page to the bookmarks bar."""
        v = self.current_view()
        if v is None:
            return
        u = v.url().toString()
        if not u.startswith("http"):
            self.toast("Only web pages can be bookmarked", 3000)
            return
        lst = self._shortcuts()
        if any(s.get("url") == u for s in lst if not isinstance(s.get("items"), list)):
            self.toast("This page is already bookmarked", 3000)
            return
        lst.append({"title": v.title() or u, "url": u})
        self._save_shortcuts(lst)
        self.toast("Added to the bookmarks bar", 3000)

    def _add_folder(self):
        from PySide6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, "New folder", "Folder name:")
        if not ok or not name.strip():
            return
        lst = self._shortcuts()
        lst.append({"title": name.strip(), "items": []})
        self._save_shortcuts(lst, refresh_page=False)

    def _add_to_folder(self, f: int):
        from PySide6.QtWidgets import QInputDialog
        from .. import pages
        lst = self._shortcuts()
        if not (0 <= f < len(lst)) or not isinstance(lst[f].get("items"), list):
            return
        url, ok = QInputDialog.getText(self, "Add to folder", "Website address (e.g. example.com):")
        if not ok or not url.strip():
            return
        url = url.strip()
        if "://" not in url:
            url = "https://" + url
        title, ok = QInputDialog.getText(self, "Add to folder", "Name:", text=pages._sc_domain(url))
        if not ok:
            return
        lst[f]["items"].append({"title": title.strip() or pages._sc_domain(url), "url": url})
        self._save_shortcuts(lst, refresh_page=False)

    def _del_in_folder(self, f: int, i: int):
        lst = self._shortcuts()
        if 0 <= f < len(lst) and isinstance(lst[f].get("items"), list) and 0 <= i < len(lst[f]["items"]):
            lst[f]["items"].pop(i)
            self._save_shortcuts(lst, refresh_page=False)

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
            elif do == "reopen-tab":
                try:
                    self.reopen_tab_at(int(params.get("i", "-1")))
                except ValueError:
                    pass
            elif do == "bg-upload" and not self.tor:
                QTimer.singleShot(0, self._pick_background_image)  # don't block the scheme request on a dialog
            elif do == "bg-upload-video" and not self.tor:
                QTimer.singleShot(0, self._pick_background_video)
            elif do == "bg-remove-image" and not self.tor:
                self._remove_background_image()
            elif do == "bg-remove-video" and not self.tor:
                self._remove_background_video()
            elif do == "weather-place" and not self.ephemeral:
                QTimer.singleShot(0, self._set_weather_place)  # don't block the scheme request on a dialog
            elif do == "weather-auto" and not self.ephemeral:
                self._clear_weather_place()
            elif do in ("weather-toggle", "location-toggle") and not self.tor:
                key = "home/weather" if do == "weather-toggle" else "home/location"
                on = not self.settings.value(key, True, type=bool)
                self.settings.setValue(key, on)
                self.settings.sync()
                if self._wx_enabled():
                    self._start_weather()        # (re)detect + fetch so whichever part is on has data
                else:
                    self._weather = None          # both off → nothing to show
                label = "Weather" if do == "weather-toggle" else "Location"
                self.toast(f"{label} {'shown' if on else 'hidden'} on the start page", 3000)
                QTimer.singleShot(0, self._refresh_home_pages)
            elif do == "sc-add" and not self.tor:
                QTimer.singleShot(0, self._add_shortcut)  # don't block the scheme request on a dialog
            elif do == "sc-folder" and not self.tor:
                QTimer.singleShot(0, self._add_folder)
            elif do == "sc-add-to" and not self.tor:
                try:
                    f = int(params.get("f", "-1"))
                except ValueError:
                    f = -1
                if f >= 0:
                    QTimer.singleShot(0, lambda f=f: self._add_to_folder(f))
            elif do == "sc-del" and not self.tor:
                try:
                    self._del_shortcut(int(params.get("i", "-1")))
                except ValueError:
                    pass
            elif do == "sc-del-url" and not self.tor:
                self._del_shortcut_url(params.get("u", ""))
            elif do == "sc-del-in" and not self.tor:
                try:
                    self._del_in_folder(int(params.get("f", "-1")), int(params.get("i", "-1")))
                except ValueError:
                    pass
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
                "bg": self._bg_settings(), "news": self._news,
                "weather_on": self.settings.value("home/weather", True, type=bool),
                "location_on": self.settings.value("home/location", True, type=bool),
                "shortcuts": None if self.tor else self._shortcuts_with_icons(),
                "weather": getattr(self, "_weather", None),
                "vid_url": self._bg_video_url(),
                "tor": bool(self.tor), "private": self.private}

    def _active_bg_video_path(self):
        """The user's uploaded background video, served by bgserver.py (built-in wallpapers are animated, no files)."""
        if self.settings.value("home/bg_mode", "", type=str) == "video_local":
            return self._custom_video_path()
        return None

    def _bg_video_url(self) -> str:
        srv = getattr(self, "bg_video_server", None)
        p = self._active_bg_video_path()
        if srv is None or p is None:
            return ""
        return f"{srv.url()}?v={int(p.stat().st_mtime)}-{p.name}"

    def _update_pd_tools(self):
        """Daily, while online: update the ProjectDiscovery tools + nuclei templates if newer ones are released."""
        if self.ephemeral or not self._is_online:
            return
        from ..security import pdtools, pdupdate
        px, verify = self.proxies(), self.verify_tls()

        def work():
            msgs = []
            n = pdupdate.check_and_update(pdtools.USER_DIR, px, verify, lambda m: msgs.append(m))
            return n, msgs

        def done(ok, res):
            if ok and res[0]:
                self.toast(f"Updated {res[0]} security tool(s) to the latest ProjectDiscovery release", 6000)
        self.runner.run(work, done)

    def _wx_enabled(self) -> bool:
        """Whether to fetch weather/location at all — true if either the weather or the location display is on."""
        return bool(self.settings.value("home/weather", True, type=bool)
                    or self.settings.value("home/location", True, type=bool))

    def _weather_place(self) -> dict | None:
        """The city the user set manually (overrides IP geolocation), or None to auto-detect from the IP."""
        import json
        raw = self.settings.value("home/weather_place", "", type=str)
        if not raw:
            return None
        try:
            p = json.loads(raw)
            if p.get("lat") is not None and p.get("lon") is not None:
                return p
        except (ValueError, TypeError):
            pass
        return None

    def _start_weather(self):
        """Begin locating for the start-page weather. Manual city wins; else try the OS location service
        (Wi-Fi/GPS, precise — like a phone's weather app); else fall back to coarse IP geolocation."""
        if self.ephemeral or not self._wx_enabled():
            return
        if self._weather_place():          # user pinned a city — no geolocation needed
            self._fetch_weather()
            return
        if self.settings.value("home/weather_os", True, type=bool) and self._start_oslocation():
            return                          # OS fix in progress; it fetches when ready (timer falls back to IP)
        self._fetch_weather()               # OS location unavailable → IP

    def _start_oslocation(self) -> bool:
        """Ask the OS for a precise position (Wi-Fi/GPS via Qt Positioning). Returns True if a request started;
        on success it reverse-geocodes + fetches weather, and a timer falls back to IP if no fix arrives."""
        try:
            from PySide6.QtPositioning import QGeoPositionInfoSource
        except Exception:  # noqa: BLE001  — Qt Positioning not available in this build
            return False
        src = QGeoPositionInfoSource.createDefaultSource(self)
        if src is None:                     # no location backend on this platform
            return False
        self._geo_src = src                 # keep a reference so it isn't garbage-collected mid-request
        state = {"done": False}

        def fallback_ip():
            if state["done"]:
                return
            state["done"] = True
            self._fetch_weather()

        def on_pos(info):
            if state["done"]:
                return
            state["done"] = True
            c = info.coordinate()
            lat, lon = c.latitude(), c.longitude()
            if not lat and not lon:         # invalid fix
                self._fetch_weather()
                return
            from .. import homeinfo
            self.runner.run(lambda: homeinfo.reverse_geocode(lat, lon, self.proxies(), self.verify_tls()),
                            lambda ok, g: (setattr(self, "_geo_place",
                                                   g or {"city": "", "country": "", "lat": lat, "lon": lon}),
                                           self._fetch_weather()))

        src.positionUpdated.connect(on_pos)
        try:
            src.errorOccurred.connect(lambda *_: fallback_ip())  # permission denied / no backend
        except (AttributeError, TypeError):
            pass
        QTimer.singleShot(8000, fallback_ip)  # no fix within 8 s → use IP
        src.requestUpdate(7000)
        return True

    def _fetch_weather(self):
        # location + weather for the start page; off in private/Tor and when the user disables it. We try even if
        # reachability reports "offline" (it misreports on some systems) — a real offline machine just fails quietly.
        if self.ephemeral or not self._wx_enabled():
            return
        from .. import homeinfo
        place = self._weather_place() or getattr(self, "_geo_place", None)  # manual city, else OS fix, else IP
        self.runner.run(lambda: homeinfo.fetch(self.proxies(), self.verify_tls(), place), self._weather_ready)

    def _set_weather_place(self):
        """Ask for a city, then let the user pick the exact match (disambiguation — the accurate pattern other
        browsers use; IP geolocation points at the ISP, not you)."""
        from PySide6.QtWidgets import QInputDialog
        cur = self._weather_place() or {}
        text, ok = QInputDialog.getText(self, "Set your location",
                                        "Search for a city (e.g. Busan, Seoul, New York) — leave empty to detect "
                                        "from your IP:", text=cur.get("city", ""))
        if not ok:
            return
        text = text.strip()
        if not text:
            self._clear_weather_place()
            return

        def done(ok2, matches):
            if not ok2 or not matches:
                self.toast(f"Couldn't find “{text}”. Try a nearby bigger city.", 5000)
                return
            self._choose_weather_place(matches)
        from .. import homeinfo
        self.toast("Searching…", 1500)
        self.runner.run(lambda: homeinfo.geocode_all(text, self.proxies(), self.verify_tls()), done)

    def _choose_weather_place(self, matches: list):
        """Show the geocoding matches so the user picks the exact place (region + country)."""
        from PySide6.QtWidgets import QInputDialog
        import json
        if len(matches) == 1:
            chosen = matches[0]
        else:
            labels = [m["label"] for m in matches]
            label, ok = QInputDialog.getItem(self, "Set your location", "Pick the right place:", labels, 0, False)
            if not ok:
                return
            chosen = next((m for m in matches if m["label"] == label), matches[0])
        place = {k: chosen[k] for k in ("city", "region", "country", "lat", "lon") if k in chosen}
        self.settings.setValue("home/weather_place", json.dumps(place))
        self.settings.sync()
        self._geo_place = None
        self.toast(f"Weather set to {chosen.get('label') or chosen.get('city', '')}", 4000)
        self._fetch_weather()

    def _clear_weather_place(self):
        self.settings.remove("home/weather_place")
        self.settings.sync()
        self._weather = None
        self._geo_place = None
        self.toast("Weather will use your device location (or IP)", 4000)
        self._start_weather()  # re-detect: OS location if allowed, else IP

    def _weather_ready(self, ok, result):
        if ok and result:
            if not self._is_online:   # we clearly reached the internet: correct a false "offline" state
                self._is_online = True
                banner = getattr(self, "offline_banner", None)
                if banner is not None:
                    banner.set_offline(False)
            if result != getattr(self, "_weather", None):
                self._weather = result
                self._refresh_home_pages()
