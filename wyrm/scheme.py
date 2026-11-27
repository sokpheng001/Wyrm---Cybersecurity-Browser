#------------------------------------------------------------------------------
# Wyrm — wyrm/scheme.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""wyrm:// URL scheme: wyrm://home and wyrm://search?q=... served from Python."""
from __future__ import annotations

import sys
import time
from pathlib import Path
from urllib.parse import parse_qs

import shiboken6
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QUrl
from PySide6.QtWebEngineCore import QWebEngineUrlRequestJob, QWebEngineUrlScheme, QWebEngineUrlSchemeHandler

from . import engines, pages, scholar
from .security import secsearch

# start-page actions the page already applies itself (client-side tile removal, in-place toggle): aborting the
# wyrm://do request keeps the current page — no reload, no extra history entry.
_STAY_ACTIONS = {"sc-del-url", "sc-edit-url", "topsite-hide",
                 "weather-toggle", "location-toggle", "topsites-toggle"}

SCHEME = b"wyrm"
ASSETS = Path(__file__).parent / "assets"

# Current new-tab wallpaper, in memory only and shared by every window: all pages and reloads reuse it
# until it is BG_ROTATE_MS old (also across restarts: cached on disk).  bytes: image | None;
# at: wall-clock time (time.time()) when its fetch started;
# waiting: jobs parked on an in-flight fetch (None = no fetch running).
_BG: dict = {"bytes": None, "at": 0.0, "waiting": None}


def register_scheme():
    """Must be called before QApplication is created."""
    s = QWebEngineUrlScheme(SCHEME)
    s.setSyntax(QWebEngineUrlScheme.Syntax.Host)
    # CorsEnabled: wyrm://home etc. may load the bundled fonts from wyrm://assets, so every OS renders the
    # same IBM Plex typeface instead of falling back to its own system font
    s.setFlags(QWebEngineUrlScheme.Flag.SecureScheme | QWebEngineUrlScheme.Flag.LocalAccessAllowed
               | QWebEngineUrlScheme.Flag.CorsEnabled)
    QWebEngineUrlScheme.registerScheme(s)


class HiddenSchemeHandler(QWebEngineUrlSchemeHandler):
    def __init__(self, library, runner, engine_getter, home_context, parent=None):
        super().__init__(parent)
        self.library = library
        self.runner = runner
        self.engine_getter = engine_getter  # -> current default engine key
        self.home_context = home_context    # -> dict for the start page
        self._cache: dict[str, dict] = {}  # query -> search results (keeps back/forward instant)
        self._sec_cache: dict[str, dict] = {}

    def bg_ms_left(self) -> int:
        """Milliseconds until the current wallpaper expires (0 = expired / none yet)."""
        if not _BG["bytes"]:
            return 0
        return max(0, int(pages.BG_ROTATE_MS - (time.time() - _BG["at"]) * 1000))

    def _bg_files(self):
        d = getattr(self, "bg_cache_dir", None)
        return (d / "wallpaper.img", d / "wallpaper.json") if d else (None, None)

    def _load_bg_cache(self):
        """After a restart: reuse the wallpaper saved on disk while it is still within its interval."""
        img, meta = self._bg_files()
        if _BG["bytes"] or not img or not img.is_file() or not meta.is_file():
            return
        try:
            import json
            at = float(json.loads(meta.read_text(encoding="utf-8")).get("at", 0))
            if time.time() - at < pages.BG_ROTATE_MS / 1000:
                _BG["bytes"], _BG["at"] = img.read_bytes(), at
        except (OSError, ValueError):
            pass

    def _save_bg_cache(self):
        img, meta = self._bg_files()
        if not img or not _BG["bytes"]:
            return
        try:
            import json
            img.parent.mkdir(parents=True, exist_ok=True)
            img.write_bytes(_BG["bytes"])
            meta.write_text(json.dumps({"at": _BG["at"]}), encoding="utf-8")
        except OSError:
            pass

    def bg_version(self) -> int:
        """Stable id of the current wallpaper (its fetch time) → stable URL the page can cache."""
        self._load_bg_cache()
        return int(_BG["at"]) if _BG["bytes"] else 0

    def _serve_bg(self, job):
        self._load_bg_cache()
        # a few seconds of slack so a page timer that fires right at expiry gets the new image
        if _BG["bytes"] and self.bg_ms_left() > 5000:
            self._reply(job, _BG["bytes"], b"image/jpeg", cache=True)
            return
        if _BG["waiting"] is not None:  # another tab already started fetching the next one
            _BG["waiting"].append(job)
            return
        _BG["waiting"] = [job]
        started = time.time()  # age counts from the request, so page timers line up with expiry

        def done(ok, res):
            waiting = _BG["waiting"] or []
            _BG["waiting"] = None
            if ok and res:
                _BG["bytes"], _BG["at"] = res, started
                self._save_bg_cache()
            # fetch failed: keep showing the previous wallpaper if there is one
            for j in waiting:
                if _BG["bytes"]:
                    self._reply(j, _BG["bytes"], b"image/jpeg", cache=True)
                elif shiboken6.isValid(j):
                    j.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)
        self.runner.run(self._fetch_bg, done)

    def requestStarted(self, job: QWebEngineUrlRequestJob):
        url = job.requestUrl()
        host = url.host()
        params = parse_qs(url.query(QUrl.ComponentFormattingOption.FullyEncoded))
        q = (params.get("q") or [""])[0].strip()

        if host == "allow":  # "continue anyway" from a warning page: only acts on an explicit user click
            # websites must not be able to whitelist themselves: only our own warning pages (opaque data: origin)
            # may call this endpoint
            initiator = job.initiator().scheme() if not job.initiator().isEmpty() else ""
            trusted = initiator in ("", "data", "wyrm")
            target = self.actions(params.get("action", [""])[0], {k: v[0] for k, v in params.items()}) \
                if trusted and getattr(self, "actions", None) else None
            if target:
                job.redirect(QUrl(target))
            else:
                job.fail(QWebEngineUrlRequestJob.Error.RequestDenied)
        elif host == "do":  # start-page actions (tiles, Customize background) — then back to home
            # only from our own pages or the address bar: a website must not be able to change settings
            initiator = job.initiator().scheme() if not job.initiator().isEmpty() else ""
            if initiator not in ("", "wyrm"):
                job.fail(QWebEngineUrlRequestJob.Error.RequestDenied)
                return
            if getattr(self, "actions", None):
                self.actions("do:" + (params.get("a") or [""])[0], {k: v[0] for k, v in params.items()})
            a = (params.get("a") or [""])[0]
            # Actions the start page already reflects on its own (a tile removed client-side, a toggle flipped in
            # place) must NOT navigate — redirecting to wyrm://home reloads the whole page (the "deleting a shortcut
            # refreshes too much" complaint) and piles up history entries so Back stops working. Abort the request
            # so the current page simply stays as it is.
            if a in _STAY_ACTIONS:
                job.fail(QWebEngineUrlRequestJob.Error.RequestAborted)
            else:
                # background choices return with the Customize panel still open
                job.redirect(QUrl("wyrm://home#customize" if a.startswith("bg") else
                                  "wyrm://history" if a.startswith("hist") else "wyrm://home"))
        elif host == "bgimg":  # the user's own start-page background (Customize → Upload)
            img = self.custom_bg() if getattr(self, "custom_bg", None) else None
            if img:
                self._reply(job, img[0], img[1], cache=True)
            else:
                job.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)
        elif host == "bg":  # random new-tab background, held in memory (never saved to disk), changes every 30 min
            self._serve_bg(job)
        elif host == "history":  # browsing history page — only our own chrome / the address bar may open it
            initiator = job.initiator().scheme() if not job.initiator().isEmpty() else ""
            if initiator not in ("", "wyrm"):   # a website must never read the user's history (SEC-10)
                job.fail(QWebEngineUrlRequestJob.Error.RequestDenied)
                return
            hp = getattr(self, "history_page", None)
            self._reply(job, hp(q) if hp else pages.render_message("History", "History is not available here."))
        elif host == "frametest":  # clickjacking proof-of-concept: frames the target locally
            target = (params.get("u") or [""])[0]
            from urllib.parse import unquote
            self._reply(job, pages.render_frametest(unquote(target)))
        elif host == "help":  # built-in user guide
            self._reply(job, pages.render_help(sys.platform == "darwin"))
        elif host == "welcome":  # first-run welcome screen
            self._reply(job, pages.render_welcome())
        elif host == "assets":  # bundled fonts for internal pages
            name = url.path().rsplit("/", 1)[-1]
            f = ASSETS / "fonts" / name
            if name.endswith(".ttf") and f.is_file():
                self._reply(job, f.read_bytes(), b"font/ttf", cors=True)
            else:
                job.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)
        elif host == "go" and q:  # start-page search box: same rules as the address bar
            job.redirect(QUrl(engines.resolve(q, self.engine_getter())))
        elif host in ("", "home", "go") or (host == "search" and not q):
            self._reply(job, pages.render_home(self._home_ctx()))
        elif host == "sec":  # HackPi Security Search (default engine)
            if not q:
                self._reply(job, pages.render_home(self._home_ctx()))
            elif q in self._sec_cache:
                self._reply(job, pages.render_sec(self._sec_cache[q]))
            else:
                def done(ok, res, q=q):
                    if ok:
                        self._sec_cache[q] = res
                    self._reply(job, pages.render_sec(res) if ok else pages.render_message("Search failed", str(res)))
                self.runner.run(secsearch.search, done, q)
        elif host == "search":
            if q in self._cache:
                self._reply(job, pages.render_results(q, self._cache[q], self.library.status_map()))
                return
            self.runner.run(scholar.search, lambda ok, res: self._search_done(job, q, ok, res), q)
        else:
            job.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)

    def _home_ctx(self) -> dict:
        ctx = dict(self.home_context())
        ctx["bg_ver"] = self.bg_version()  # also loads a still-valid wallpaper from disk after a restart
        ctx["bg_ms_left"] = self.bg_ms_left()
        return ctx

    def _search_done(self, job, q, ok, res):
        if ok:
            if res["results"]:
                self._cache[q] = res
            html = pages.render_results(q, res, self.library.status_map())
        else:
            html = pages.render_message("Search failed", f"Search failed: {res}")
        self._reply(job, html)

    @staticmethod
    def _fetch_bg():
        """Fetch one random Cambodia photo live (no disk cache). Tries each source; returns bytes or None."""
        import requests
        s = requests.Session()
        s.trust_env = False
        for src in pages.BG_SOURCES:
            try:
                r = s.get(src, timeout=20, allow_redirects=True,
                          headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Wyrm/1.0"})
                if r.ok and r.content and r.headers.get("content-type", "").startswith("image"):
                    return r.content
            except requests.RequestException:
                continue
        return None

    @staticmethod
    def _reply(job, content, ctype: bytes = b"text/html", cors: bool = False, cache: bool = False):
        if not shiboken6.isValid(job):  # user navigated away while we were fetching
            return
        buf = QBuffer(job)
        buf.setData(QByteArray(content.encode("utf-8") if isinstance(content, str) else content))
        buf.open(QIODevice.OpenModeFlag.ReadOnly)
        try:  # wyrm:// pages are dynamic (theme/mode/feed) — never cache them
            # images under a versioned URL may be cached (going back Home shows them instantly)
            headers = {QByteArray(b"Cache-Control"): QByteArray(b"private, max-age=86400" if cache else b"no-store")}
            if cors:  # static bundled assets (fonts) only — never dynamic pages
                headers[QByteArray(b"Access-Control-Allow-Origin")] = QByteArray(b"*")
            job.setAdditionalResponseHeaders(headers)
        except (TypeError, AttributeError):
            pass
        job.reply(QByteArray(ctype), buf)
