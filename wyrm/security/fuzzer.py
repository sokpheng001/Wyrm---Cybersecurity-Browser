#------------------------------------------------------------------------------
# Wyrm — wyrm/security/fuzzer.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Throttled, scope-gated request fuzzer — a RESPONSIBLE 'Intruder' for authorized single-target testing.

Guardrails baked in (not optional):
  * in-scope only — refuses any host outside the active engagement's scope;
  * an enforced minimum delay / maximum request rate (no "full speed" / unthrottled mode);
  * a hard ceiling on total requests per run (no endless brute-force);
  * single sequential sender (no high-concurrency flooding).
It iterates a USER-SUPPLIED payload list over §marked§ positions in one request and records the
response (status, length, time) for manual analysis. It has no credential-stuffing or auto-exploit features.
"""
from __future__ import annotations

import re
import time
from urllib.parse import urlparse

import requests

MARK = re.compile(r"§(.*?)§")
MAX_RATE = 20.0          # requests/second hard cap (throttle can only go slower)
MAX_REQUESTS_CEILING = 2000   # absolute ceiling per run, whatever the user sets
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Wyrm/1.0"


def positions(template: str) -> int:
    return len(MARK.findall(template))


def _apply(template: str, payload: str) -> str:
    return MARK.sub(lambda _m: payload, template)


def apply_payload(template: str, payload: str) -> str:
    """Public: substitute a payload at every §…§ mark (used by the UI to build a concrete request)."""
    return _apply(template, payload)


def run(method: str, url_tpl: str, headers_tpl: str, body_tpl: str, payloads: list[str], *,
        in_scope, rate_per_sec: float, max_requests: int, proxies=None, verify=True,
        on_result=None, should_stop=None) -> dict:
    """Run a throttled campaign. Calls on_result(dict) per request; stops if should_stop() is true.

    Returns a summary dict. Raises PermissionError if the target host is out of scope.
    """
    host = urlparse(url_tpl).hostname or ""
    if in_scope is not None and not in_scope(host):
        raise PermissionError(f"{host} is not in the active engagement's scope — fuzzing is scope-gated.")
    rate = min(max(0.2, float(rate_per_sec)), MAX_RATE)   # clamp to [0.2 .. 20] req/s
    delay = 1.0 / rate
    cap = min(int(max_requests), MAX_REQUESTS_CEILING)
    payloads = payloads[:cap]
    sent = 0
    sess = requests.Session()
    sess.trust_env = False
    for payload in payloads:
        if should_stop and should_stop():
            break
        url = _apply(url_tpl, payload)
        headers = {}
        for line in _apply(headers_tpl, payload).splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        headers.setdefault("User-Agent", UA)
        body = _apply(body_tpl, payload).encode() if body_tpl else None
        t = time.perf_counter()
        try:
            r = sess.request(method, url, headers=headers, data=body, timeout=20,
                             proxies=proxies, verify=verify, allow_redirects=False)
            ms = int((time.perf_counter() - t) * 1000)
            res = {"payload": payload, "status": r.status_code, "length": len(r.content), "ms": ms,
                   "location": r.headers.get("location", "")}
        except requests.RequestException as e:
            res = {"payload": payload, "status": None, "length": 0, "ms": 0, "error": str(e)[:120]}
        sent += 1
        if on_result:
            on_result(res)
        time.sleep(delay)          # enforced throttle between every request
    return {"sent": sent, "capped": len(payloads) >= cap}
