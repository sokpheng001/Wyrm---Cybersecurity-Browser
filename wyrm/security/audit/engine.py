#------------------------------------------------------------------------------
# Wyrm — wyrm/security/audit/engine.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Sopi, Kwan
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

from . import passive as passive_mod
from . import points as points_mod
from .checks import ALL_CHECKS


def _rand(n=6):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def scan(request: dict, send, checks=None, should_stop=None, on_finding=None, passive=True, oob=None,
         seen=None) -> list[dict]:
    """Audit one request. `send(method, url, headers, body)` performs a request (scope is the caller's job).
    Pass a shared `seen` set to de-duplicate findings across several requests (see scan_site)."""
    checks = checks if checks is not None else ALL_CHECKS
    should_stop = should_stop or (lambda: False)
    rand = _rand()
    method = request.get("method", "GET")
    url = request["url"]
    headers = dict(request.get("headers") or {})
    body = request.get("body", "") or ""

    def bound(u, h, b):   # bind this request's method so checks call send(url, headers, body)
        return send(method, u, h, b)

    baseline = bound(url, headers, body)
    findings: list[dict] = []
    seen = seen if seen is not None else set()

    def emit(f):
        key = (f["check"], f["loc"], f["param"], f["title"])
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

    for point, build in points_mod.insertion_points(method, url, headers, body):
        if should_stop():
            break
        for chk in checks:
            if should_stop():
                break
            try:
                f = chk.run(point, build, bound, baseline, rand, oob)
            except Exception:  # noqa: BLE001 - one check failing must not stop the scan
                f = None
            if f:
                emit(f)
    return findings


def scan_site(requests_list, send, checks=None, should_stop=None, on_finding=None, oob=None,
              on_progress=None) -> list[dict]:
    """Audit many requests (e.g. every in-scope request seen through the proxy) with findings de-duplicated across
    all of them. on_progress(done, total, url) reports progress."""
    should_stop = should_stop or (lambda: False)
    seen = set()
    out: list[dict] = []
    n = len(requests_list)
    for i, req in enumerate(requests_list):
        if should_stop():
            break
        if on_progress is not None:
            try:
                on_progress(i + 1, n, req.get("url", ""))
            except Exception:  # noqa: BLE001
                pass
        out += scan(req, send, checks=checks, should_stop=should_stop, on_finding=on_finding, oob=oob, seen=seen)
    return out
