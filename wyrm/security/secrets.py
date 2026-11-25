#------------------------------------------------------------------------------
# Wyrm — wyrm/security/secrets.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""One shared secret detector for every tool (QA-H4).

Overview, Scanner/JS recon and the Audit passive checks all used to carry their own, drifting secret lists — the
same leak was reported with different names and severities, and the "generic secret" rule missed any identifier
that wasn't *exactly* the keyword (so SECRET_TOKEN / DB_PASSWORD / API_SECRET_KEY slipped through). This module
is the single source of truth: one PATTERNS list plus find_secrets(text), returning (name, matched, severity,
start, end). Callers keep their own output shape and redaction.
"""
from __future__ import annotations

import re

# Specific, high-signal brand patterns: (name, regex, severity, value_group). value_group is the regex group
# holding the secret itself (0 = the whole match), used for redaction and overlap de-duplication.
PATTERNS: list[tuple[str, "re.Pattern[str]", str, int]] = [
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high", 0),
    ("AWS secret access key", re.compile(r"(?i)aws.{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]"), "high", 1),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "high", 0),
    ("Google OAuth client secret", re.compile(r"\bGOCSPX-[0-9A-Za-z_\-]{20,}\b"), "high", 0),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b"), "high", 0),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[0-9A-Za-z_]{22,}\b"), "high", 0),
    ("Slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), "high", 0),
    ("Slack webhook", re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+"), "medium", 0),
    ("Stripe secret key", re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"), "high", 0),
    ("Twilio API key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high", 0),
    ("SendGrid API key", re.compile(r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b"), "high", 0),
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-f]{32}\b"), "medium", 0),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "high", 0),
]

# Generic rule: an identifier that CONTAINS a secret keyword (with any prefix/suffix word chars — the bug that
# QA-H4 fixes), then an optional quote, an assignment, and a quoted value of 8+ non-space chars.
_GENERIC = re.compile(
    r"""(?ix)
    [A-Za-z0-9_]*                                   # optional prefix word chars (PREFIX_SECRET_SUFFIX)
    (?:secret|token|passw(?:or)?d|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret)
    [A-Za-z0-9_]*                                   # optional suffix word chars
    ["']?\s*[:=]\s*["']([^"'\s]{8,})["']            # = "value" (group 1)
    """)

# Obvious placeholders that aren't real secrets.
_PLACEHOLDER = re.compile(
    r"(?ix)^(?:x+|changeme\d*|placeholder|example[\w-]*|your[_-][\w-]*|[\w-]*_here|<.*>|\$\{.*\}"
    r"|process\.env[\w.]*|null|none|undefined|true|false)$")

_GENERIC_SEVERITY = "medium"
_GENERIC_NAME = "Hard-coded secret"


def find_secrets(text: str):
    """[(name, matched, severity, start, end)] for secrets in `text`, de-duplicated and position-sorted."""
    if not text:
        return []
    out: list[tuple[str, str, str, int, int]] = []
    taken: list[tuple[int, int]] = []

    def overlaps(s: int, e: int) -> bool:
        return any(s < te and e > ts for ts, te in taken)

    for name, rx, sev, grp in PATTERNS:
        for m in rx.finditer(text):
            s, e = m.span(grp)
            if overlaps(s, e):
                continue
            taken.append((s, e))
            out.append((name, m.group(grp), sev, s, e))
    for m in _GENERIC.finditer(text):
        s, e = m.span(1)
        val = m.group(1)
        if overlaps(s, e) or _PLACEHOLDER.match(val):
            continue
        taken.append((s, e))
        out.append((_GENERIC_NAME, val, _GENERIC_SEVERITY, s, e))
    out.sort(key=lambda t: t[3])
    return out
