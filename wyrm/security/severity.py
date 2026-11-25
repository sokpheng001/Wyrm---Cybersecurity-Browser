#------------------------------------------------------------------------------
# Wyrm — wyrm/security/severity.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Canonical severity levels and the default severities for the checks that several tools share (QA-M1).

Overview (analyzer), Scanner (webchecks) and Audit (passive) each used to pick their own severity for the same
weakness — a missing CSP was medium in one and low in another, and labels were shown as 'medium' / 'MEDIUM' /
'WARNING'. This module is the single source of truth: DEFAULTS for the shared header/cookie checks, and title()
for consistent display.
"""
from __future__ import annotations

LEVELS = ("critical", "high", "medium", "low", "info")

# Default severities for the header/cookie weaknesses reported by more than one tool.
DEFAULTS = {
    "missing-csp": "medium",
    "missing-clickjacking": "medium",
    "missing-hsts": "medium",
    "missing-nosniff": "low",
    "cookie-no-secure": "medium",
    "cookie-no-httponly": "low",
    "server-version": "info",
    "powered-by": "info",
}


def default(key: str) -> str:
    return DEFAULTS.get(key, "info")


def title(sev: str) -> str:
    """Display form of a severity in Title case: 'medium' -> 'Medium'. Unknown values are returned unchanged."""
    s = (sev or "").lower()
    return s.title() if s in LEVELS else (sev or "")


def rank(sev: str) -> int:
    """Sort key: critical=0 … info=4, unknown last."""
    s = (sev or "").lower()
    return LEVELS.index(s) if s in LEVELS else len(LEVELS)
