#------------------------------------------------------------------------------
# Wyrm — wyrm/security/audit/engine.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Drive the active checks over a request's insertion points, plus passive checks on the baseline, de-duplicating
findings and reporting each as it is confirmed.

    scan(request, send, ...) -> [finding, …]

`request` = {"method", "url", "headers" (dict), "body" (str)}. `send(url, headers, body)` performs one request
(the caller fixes the method and scope) and returns a response dict or None. Findings are de-duplicated by
(check, location, parameter)."""
from __future__ import annotations

import random
import string
import threading
import time

from . import passive as passive_mod
from . import points as points_mod
from .checks import ALL_CHECKS


def _rand(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


class RateLimiter:
    """Caps the total request rate across all scanner threads (be polite to the target)."""

    def __init__(self, per_sec: float):
        self._min = (1.0 / per_sec) if per_sec and per_sec > 0 else 0.0
        self._lock = threading.Lock()
        self._next = 0.0

    def acquire(self):
        if self._min <= 0:
            return
        with self._lock:
            now = time.monotonic()
            wait = self._next - now
            if wait > 0:
                time.sleep(wait)
            self._next = max(now, self._next) + self._min


def scan(request: dict, send, checks=None, should_stop=None, on_finding=None, passive=True, oob=None,
         seen=None, lock=None, max_requests: int = 2500) -> list[dict]:
    """Audit one request. `send(method, url, headers, body)` performs a request (scope is the caller's job).
    Pass a shared `seen` set (and `lock`) to de-duplicate findings across several concurrent requests (scan_site).
    `max_requests` caps how many probe requests this scan may send to the target (safety / politeness); the scan
    stops gracefully once it's reached."""
    checks = checks if checks is not None else ALL_CHECKS
    _user_stop = should_stop or (lambda: False)
    rand = _rand()
    method = request.get("method", "GET")
    url = request["url"]
    headers = dict(request.get("headers") or {})
    body = request.get("body", "") or ""

    sent = [0]

    def bound(u, h, b):   # bind this request's method so checks call send(url, headers, body)
        sent[0] += 1
        return send(method, u, h, b)

    def should_stop():    # stop on the caller's request OR once the per-scan request budget is spent
        return _user_stop() or sent[0] >= max_requests

    baseline = bound(url, headers, body)
    findings: list[dict] = []
    seen = seen if seen is not None else set()
    _lock = lock if lock is not None else threading.Lock()

    def emit(f):
        key = (f["check"], f["loc"], f["param"], f["title"])
        with _lock:
            if key in seen:
                return
            seen.add(key)
            findings.append(f)
        if on_finding is not None:
            try:
                on_finding(f)
            except Exception:  # noqa: BLE001
                pass

    if passive and baseline:
        for f in passive_mod.check_response(url, baseline):
            emit(f)

    # request-level checks (run once per request, not per insertion point) — e.g. CORS misconfiguration
    for chk in checks:
        if should_stop():
            break
        runner = getattr(chk, "run_request", None)
        if runner is None:
            continue
        try:
            f = runner(method, url, headers, body, bound, baseline, rand, oob)
        except Exception:  # noqa: BLE001 - one check failing must not stop the scan
            f = None
        if f:
            emit(f)

    for point, build in points_mod.insertion_points(method, url, headers, body):
        if should_stop():
            break
        for chk in checks:
            if should_stop():
                break
            runner = getattr(chk, "run", None)   # some checks are request-level only (no per-point run)
            if runner is None:
                continue
            try:
                f = runner(point, build, bound, baseline, rand, oob)
            except Exception:  # noqa: BLE001 - one check failing must not stop the scan
                f = None
            if f:
                emit(f)
    return findings


def scan_site(requests_list, send, checks=None, should_stop=None, on_finding=None, oob=None,
              on_progress=None, workers=6, rate=12.0) -> list[dict]:
    """Audit many requests concurrently (up to `workers` at once), capped to `rate` requests/sec in total, with
    findings de-duplicated across all of them. on_progress(done, total, url) reports progress."""
    from concurrent.futures import ThreadPoolExecutor

    should_stop = should_stop or (lambda: False)
    seen: set = set()
    lock = threading.Lock()
    limiter = RateLimiter(rate)
    out: list[dict] = []
    n = len(requests_list)
    done = [0]

    def limited_send(method, url, headers, body):
        limiter.acquire()
        return send(method, url, headers, body)

    def one(req):
        if should_stop():
            return []
        fs = scan(req, limited_send, checks=checks, should_stop=should_stop, on_finding=on_finding, oob=oob,
                  seen=seen, lock=lock)
        with lock:
            done[0] += 1
            d = done[0]
        if on_progress is not None:
            try:
                on_progress(d, n, req.get("url", ""))
            except Exception:  # noqa: BLE001
                pass
        return fs

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for fs in ex.map(one, requests_list):
            out += fs
    return out
