#------------------------------------------------------------------------------
# Wyrm — wyrm/security/sessionauth.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Session / auth macros (Burp "session handling", Caido "authentication").

A login macro is a single HTTP request that logs in. Wyrm watches proxy responses for a logged-out signal
(a 401/403, or a body regex you set); when it sees one, it re-runs the macro off to the side, collects the fresh
session cookies and injects them into subsequent in-scope requests — so long test runs don't die when the
session expires. The macro request goes straight to the server (not back through our own proxy), so it never
loops. Config persists to sessionauth.json; captured cookies stay in memory for the session.
"""
from __future__ import annotations

import json
import re
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from . import mitm


def _set_cookie_header(headers: list, value: str):
    headers[:] = [(k, v) for k, v in headers if k.lower() != "cookie"]
    if value:
        headers.append(("Cookie", value))


class SessionAuth:
    """Holds the login macro + logged-out rule, runs the macro, and injects fresh cookies into traffic."""

    MIN_INTERVAL = 8.0   # don't re-run the macro more than this often, even under a flood of 401s

    def __init__(self):
        self.data: dict = {"enabled": False, "macro": {"method": "POST", "url": "", "headers": [], "body": ""},
                           "match_hosts": "", "logout_status": [401, 403], "logout_regex": ""}
        self.path: Path | None = None
        self.cookies: dict[str, str] = {}
        self.log: list[str] = []
        self.notify = None
        self._lock = threading.Lock()
        self._running = False
        self._last = 0.0

    # -------------------------------------------------- persistence
    def load(self, path: Path):
        self.path = path
        try:
            d = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(d, dict):
                self.data.update(d)
        except (OSError, ValueError):
            pass
        return self

    def save(self):
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
        except OSError:
            pass

    # -------------------------------------------------- install on the proxy
    def install(self, proxy):
        if self._inject not in proxy.request_rewriters:
            proxy.request_rewriters.append(self._inject)
        if self._observe not in proxy.response_observers:
            proxy.response_observers.append(self._observe)

    # -------------------------------------------------- scope
    def _macro_host(self) -> str:
        return (urlparse(self.data.get("macro", {}).get("url", "")).hostname or "").lower()

    def _host_match(self, host: str) -> bool:
        mh = (self.data.get("match_hosts") or "").strip().lower()
        host = (host or "").lower()
        if mh:
            return mh in host
        mhost = self._macro_host()
        return bool(mhost) and host == mhost

    # -------------------------------------------------- request injection (proxy thread)
    def _inject(self, req):
        if not self.data.get("enabled") or not self.cookies:
            return
        if not self._host_match(req.get("host", "")):
            return
        existing = mitm._header(req["headers"], "cookie") or ""
        jar = {}
        for part in existing.split(";"):
            if "=" in part:
                k, _, val = part.strip().partition("=")
                jar[k] = val
        jar.update(self.cookies)   # our fresh cookies win
        _set_cookie_header(req["headers"], "; ".join(f"{k}={v}" for k, v in jar.items()))

    # -------------------------------------------------- logged-out detection (proxy thread)
    def _observe(self, flow):
        if not self.data.get("enabled"):
            return
        if not self.data.get("macro", {}).get("url"):
            return
        if not self._host_match(flow.get("host", "")):
            return
        if flow.get("url", "").split("?")[0] == self.data["macro"]["url"].split("?")[0]:
            return   # never treat the login request's own response as "logged out"
        if not self._looks_logged_out(flow):
            return
        self.trigger()

    def _looks_logged_out(self, flow) -> bool:
        if flow.get("status") in (self.data.get("logout_status") or []):
            return True
        rx = (self.data.get("logout_regex") or "").strip()
        if rx:
            try:
                body = mitm.decode_body(flow.get("resp_headers", []), flow.get("resp_body", b""))
                if re.search(rx, body, re.I):
                    return True
            except re.error:
                pass
        return False

    # -------------------------------------------------- run the macro
    def trigger(self):
        """Re-run the login macro in the background (throttled), to refresh the session."""
        now = time.time()
        with self._lock:
            if self._running or now - self._last < self.MIN_INTERVAL:
                return
            self._running = True
            self._last = now
        threading.Thread(target=self._run_safe, args=(True,), daemon=True).start()

    def run_now(self):
        with self._lock:
            if self._running:
                return
            self._running = True
            self._last = time.time()
        threading.Thread(target=self._run_safe, args=(False,), daemon=True).start()

    def _run_safe(self, automatic):
        try:
            self._run(automatic)
        finally:
            with self._lock:
                self._running = False

    def _run(self, automatic):
        m = self.data.get("macro", {})
        url = m.get("url", "")
        if not url:
            return
        try:
            import certifi
            import requests
            sess = requests.Session()
            headers = {k: v for k, v in m.get("headers", []) if k.lower() not in ("content-length", "host")}
            body = m.get("body") or None
            r = sess.request(m.get("method", "POST"), url, data=body, headers=headers, timeout=30,
                             verify=certifi.where(), allow_redirects=True)
            jar = requests.utils.dict_from_cookiejar(sess.cookies)
            if jar:
                self.cookies.update(jar)
            why = "auto re-login (logged-out response)" if automatic else "manual run"
            self._add_log(f"{time.strftime('%H:%M:%S')} · {why}: {m.get('method')} {url} → "
                          f"HTTP {r.status_code}, {len(jar)} cookie(s), {len(self.cookies)} held")
        except Exception as e:  # noqa: BLE001
            self._add_log(f"{time.strftime('%H:%M:%S')} · macro failed: {e}")

    def clear_cookies(self):
        self.cookies.clear()
        self._add_log(f"{time.strftime('%H:%M:%S')} · cleared held session cookies")

    def _add_log(self, line):
        self.log.append(line)
        del self.log[:-200]
        if self.notify is not None:
            try:
                self.notify()
            except Exception:  # noqa: BLE001
                pass
