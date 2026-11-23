#------------------------------------------------------------------------------
# Wyrm — wyrm/browser/interceptor.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Network request interceptor: Shields blocking, HTTPS-Only upgrades, traffic capture."""
from __future__ import annotations

from datetime import datetime

from PySide6.QtCore import QTimer, QUrl
from PySide6.QtWebEngineCore import QWebEngineUrlRequestInterceptor

from .. import linkguard
from ..shields import PageStats


class TrafficInterceptor(QWebEngineUrlRequestInterceptor):
    """Sees every request the engine makes: logs it, checks scope, blocks out-of-scope in strict mode."""

    def __init__(self, win):
        super().__init__(win)
        self.win = win

    """Per-tab request pipeline, in order:
    HTTPS-Only upgrade → tracking-parameter stripping → threat lists (malware/phishing) → smart link check →
    ads/trackers (Brave adblock engine + HackPi heuristics) → engagement scope → traffic log."""

    def __init__(self, win, view):
        super().__init__(view)
        self.win = win
        self.view = view

    def interceptRequest(self, info):
        url = info.requestUrl()
        scheme = url.scheme()
        if scheme not in ("http", "https", "ws", "wss"):
            return
        win, view = self.win, self.view
        host = url.host()
        u = url.toString()
        rtype = info.resourceType().name.replace("ResourceType", "")
        main = rtype == "MainFrame"
        first = info.firstPartyUrl()
        fp_host = host if main else (first.host() or host)
        if main and view.stats.host != host:
            view.stats = PageStats(host=host)
        st = view.stats
        sh = win.shields

        # 0. Intercept (Burp-style): hold top-level page requests for the user to edit / forward / drop
        if main and win.intercept_on:
            if u in win._intercept_pass:
                win._intercept_pass.discard(u)   # forwarded from the Intercept window: let it through once
            else:
                held = {"method": "GET", "url": u, "headers": {}, "body": b""}
                try:
                    held["method"] = bytes(info.requestMethod()).decode() or "GET"
                    held["headers"] = {bytes(k).decode(): bytes(v).decode() for k, v in info.httpHeaders().items()}
                    dev = info.requestBody()
                    if dev is not None and dev.isReadable():
                        held["body"] = bytes(dev.readAll())
                except Exception:  # noqa: BLE001 - details differ between Qt versions
                    pass
                info.block(True)
                QTimer.singleShot(0, lambda v=view, h=held: win.intercept_hold(v, h))  # leave the interceptor first
                return

        # 1. encrypt: upgrade plain HTTP/WS to HTTPS/WSS (local/lab hosts and user exceptions excluded)
        if scheme in ("http", "ws") and win.https_only() and not linkguard.is_private_host(host) \
                and host not in win.http_allowed:
            nu = QUrl(url)
            nu.setScheme("https" if scheme == "http" else "wss")
            if nu.port() == 80:
                nu.setPort(-1)
            win.upgraded_hosts.add(host)
            st.counts["upgraded"] += 1
            info.redirect(nu)
            return
        # 2. strip click-tracking parameters from navigations
        if main and sh.enabled("params"):
            clean = linkguard.strip_tracking(u)
            if clean != u:
                st.counts["params"] += 1
                info.redirect(QUrl(clean))
                return
        # 3-5. threats, smart link check, ads & trackers
        cat = None
        if host not in sh.malware_allow:
            cat = sh.check(u, first.toString(), rtype, fp_host)
            if main and cat is None and sh.enabled("linkguard"):
                verdict = linkguard.analyze(u)
                # always ask before opening a dangerous OR suspicious link (user preference)
                if verdict["verdict"] in ("dangerous", "suspicious"):
                    cat = "suspicious"
                    win.block_reasons[u] = ("suspicious", verdict)
        if cat is None and not main and sh.enabled("trackers") and sh.site_enabled(fp_host) \
                and linkguard.heuristic_tracker(u, fp_host, rtype):
            cat = "trackers"
        if cat:
            info.block(True)
            key = {"suspicious": "phishing"}.get(cat, cat)
            st.counts[key] = st.counts.get(key, 0) + 1
            st.blocked.append((cat, u, rtype))
            sh.count()
            if main and u not in win.block_reasons:
                win.block_reasons[u] = (cat, linkguard.analyze(u, threat=cat))
            win.on_blocked(view)
        # 6. engagement scope
        eng = win.engagement
        in_scope = eng.in_scope(host) if eng else None
        scope_block = bool(eng and eng.block_out_of_scope and in_scope is False)
        if scope_block and not cat:
            info.block(True)
        # 6b. Match & Replace (pentester): rewrite request headers for in-scope hosts only
        if not cat and in_scope and win.rules.active():
            try:
                cur = {bytes(k).decode(): bytes(v).decode() for k, v in info.httpHeaders().items()}
            except Exception:  # noqa: BLE001
                cur = {}
            for name, val in win.rules.apply(host, cur).items():
                info.setHttpHeader(name.encode(), b"" if val is None else val.encode())
        # 7. log
        try:
            method = bytes(info.requestMethod()).decode()
        except Exception:  # noqa: BLE001
            method = "GET"
        headers = {}
        try:
            headers = {bytes(k).decode(): bytes(v).decode() for k, v in info.httpHeaders().items()}
        except Exception:  # noqa: BLE001 - not available on every Qt version
            pass
        path = url.path() + ("?" + url.query() if url.hasQuery() else "")
        win.security.traffic.add({
            "time": datetime.now().strftime("%H:%M:%S"), "method": method, "type": rtype + (f" [{cat}]" if cat else ""),
            "host": host, "path": path or "/", "url": u, "in_scope": in_scope, "blocked": bool(cat) or scope_block,
            "headers": headers,
        })
