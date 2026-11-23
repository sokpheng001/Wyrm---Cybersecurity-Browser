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


def scan(request: dict, send, checks=None, should_stop=None, on_finding=None, passive=True, oob=None) -> list[dict]:
    checks = checks if checks is not None else ALL_CHECKS
    should_stop = should_stop or (lambda: False)
    rand = _rand()
    method = request.get("method", "GET")
    url = request["url"]
    headers = dict(request.get("headers") or {})
    body = request.get("body", "") or ""

    baseline = send(url, headers, body)
    findings: list[dict] = []
    seen = set()

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
                f = chk.run(point, build, send, baseline, rand, oob)
            except Exception:  # noqa: BLE001 - one check failing must not stop the scan
                f = None
            if f:
                emit(f)
    return findings
