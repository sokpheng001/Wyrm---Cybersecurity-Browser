"""wyrm:// URL scheme: wyrm://home and wyrm://search?q=... served from Python."""
from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs

import shiboken6
from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QUrl
from PySide6.QtWebEngineCore import QWebEngineUrlRequestJob, QWebEngineUrlScheme, QWebEngineUrlSchemeHandler

from . import engines, pages, scholar
from .security import secsearch

SCHEME = b"wyrm"
ASSETS = Path(__file__).parent / "assets"


def register_scheme():
    """Must be called before QApplication is created."""
    s = QWebEngineUrlScheme(SCHEME)
    s.setSyntax(QWebEngineUrlScheme.Syntax.Host)
    s.setFlags(QWebEngineUrlScheme.Flag.SecureScheme | QWebEngineUrlScheme.Flag.LocalAccessAllowed)
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
        elif host == "assets":  # bundled fonts for internal pages
            name = url.path().rsplit("/", 1)[-1]
            f = ASSETS / "fonts" / name
            if name.endswith(".ttf") and f.is_file():
                self._reply(job, f.read_bytes(), b"font/ttf")
            else:
                job.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)
        elif host == "go" and q:  # start-page search box: same rules as the address bar
            job.redirect(QUrl(engines.resolve(q, self.engine_getter())))
        elif host in ("", "home", "go") or (host == "search" and not q):
            self._reply(job, pages.render_home(self.home_context()))
        elif host == "sec":  # HackPi Security Search (default engine)
            if not q:
                self._reply(job, pages.render_home(self.home_context()))
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

    def _search_done(self, job, q, ok, res):
        if ok:
            if res["results"]:
                self._cache[q] = res
            html = pages.render_results(q, res, self.library.status_map())
        else:
            html = pages.render_message("Search failed", f"Search failed: {res}")
        self._reply(job, html)

    @staticmethod
    def _reply(job, content, ctype: bytes = b"text/html"):
        if not shiboken6.isValid(job):  # user navigated away while we were fetching
            return
        buf = QBuffer(job)
        buf.setData(QByteArray(content.encode("utf-8") if isinstance(content, str) else content))
        buf.open(QIODevice.OpenModeFlag.ReadOnly)
        job.reply(QByteArray(ctype), buf)
