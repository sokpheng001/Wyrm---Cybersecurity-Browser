#------------------------------------------------------------------------------
# Wyrm — wyrm/security/audit/__init__.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Active + passive web vulnerability auditing (scope-gated), built on the proxy's request pipeline.

    points.py   — parse a request into testable insertion points (query/body/json/cookie/header)
    checks.py   — active checks (reflected XSS, error + blind/time-based SQLi, SSTI, path traversal,
                  open redirect, CRLF, SSRF, OS command injection)
    passive.py  — passive checks on a response (missing security headers, cookie flags, verbose errors…)
    engine.py   — drive the checks over the insertion points, de-duplicate, score confidence
"""
from . import advice, checks, engine, passive, points, spider  # noqa: F401
