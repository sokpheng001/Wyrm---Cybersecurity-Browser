#------------------------------------------------------------------------------
# Wyrm — wyrm/security/jsrecon.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""JavaScript recon for the open page: pull endpoints / API paths and leaked secrets out of its scripts.

Works on the page you have open (like LinkFinder + SecretFinder): the browser already fetched every script, so
Wyrm scans the inline scripts and the external script bodies it downloads. Findings:
  - endpoints: URLs, API paths, and interesting words (admin, token, upload, graphql, ...) in paths
  - secrets:   API keys / tokens with a known shape (AWS, Google, GitHub, Stripe, JWT, Slack, private keys, ...)

Only scripts from the page's own origin and its subdomains are downloaded, so recon stays on the target.
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

# Secret patterns (name, regex, severity). Shapes are specific so false positives stay low.
SECRETS: list[tuple[str, str, str]] = [
    ("AWS access key ID", r"\bAKIA[0-9A-Z]{16}\b", "high"),
    ("AWS secret access key", r"(?i)aws.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "high"),
    ("Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "high"),
    ("Google OAuth client ID", r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", "medium"),
    ("GitHub token", r"\bgh[pousr]_[0-9A-Za-z]{36}\b", "high"),
    ("GitHub fine-grained token", r"\bgithub_pat_[0-9A-Za-z_]{22,}\b", "high"),
    ("Slack token", r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "high"),
    ("Slack webhook", r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+", "medium"),
    ("Stripe secret key", r"\bsk_live_[0-9A-Za-z]{24,}\b", "high"),
    ("Stripe publishable key", r"\bpk_live_[0-9A-Za-z]{24,}\b", "low"),
    ("Twilio API key", r"\bSK[0-9a-fA-F]{32}\b", "high"),
    ("SendGrid API key", r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b", "high"),
    ("Mailgun API key", r"\bkey-[0-9a-f]{32}\b", "medium"),
    ("Firebase cloud messaging key", r"\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}\b", "high"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----", "high"),
    ("JSON Web Token (JWT)", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "medium"),
    ("Authorization: Bearer", r"(?i)bearer\s+[a-z0-9._\-]{20,}", "low"),
    ("Generic api key / secret", r"(?i)(?:api[_-]?key|secret|access[_-]?token|client[_-]?secret)"
                                 r"['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_.]{16,45}['\"]", "low"),
]

# Endpoints: full URLs, and quoted paths / API routes. Deliberately close to LinkFinder's regex.
_LINK_RE = re.compile(r"""
  (?:"|')                              # opening quote
  (
    ((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})   # absolute URL
    |
    ((?:/|\.\./|\./)[^"'><,;|*()%%$^\s]{1,}[^"'><,;|*()%%$^\s:]) # relative path
    |
    ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:php|asp|aspx|jsp|json|js|action|html|do|xml)(?:[?#][^"']*)?)
    |
    ([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-]{3,}(?:[?][^"']{0,}|))     # api/v1/users style
  )
  (?:"|')
""", re.VERBOSE)

# Words that make an endpoint worth a closer look (shown first).
_INTERESTING = re.compile(r"(?i)\b(admin|internal|debug|token|secret|key|passwd|password|upload|delete|graphql|"
                          r"api[_-]?key|private|config|backup|\.git|swagger|actuator|/v\d+/|oauth|sso|jwt|redirect)")

_SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".css",
             ".mp4", ".webm", ".mp3")

# MIME types and other "word/word" noise that the relative-path regex catches but aren't endpoints.
_MIME_RE = re.compile(r"^(?:text|application|image|audio|video|multipart|font|model|message)/[\w.+-]+$", re.I)


def _same_scope(url: str, base_host: str) -> bool:
    try:
        h = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return bool(h) and (h == base_host or h.endswith("." + base_host) or base_host.endswith("." + h))


def find_secrets(text: str) -> list[tuple[str, str, str]]:
    """[(name, matched snippet, severity)] for secrets in one blob of script text."""
    out = []
    seen = set()
    for name, pat, sev in SECRETS:
        for m in re.finditer(pat, text):
            snippet = m.group(0)
            key = (name, snippet)
            if key in seen:
                continue
            seen.add(key)
            out.append((name, snippet if len(snippet) < 120 else snippet[:117] + "…", sev))
    return out


def find_endpoints(text: str, base_url: str) -> list[str]:
    """Absolute + relative endpoints referenced in one blob of script text."""
    out = set()
    for m in _LINK_RE.finditer(text):
        ep = m.group(1)
        if not ep or len(ep) > 400 or ep in ("//", "/"):
            continue
        low = ep.lower().split("?")[0]
        if low.endswith(_SKIP_EXT) or _MIME_RE.match(ep):
            continue
        out.add(ep)
    return sorted(out)


def rank_endpoints(endpoints: set[str], base_url: str) -> list[tuple[str, str, bool]]:
    """[(absolute_url, shown, interesting)] sorted interesting-first then alphabetically."""
    rows = []
    for ep in endpoints:
        try:
            absolute = urljoin(base_url, ep) if not ep.startswith(("http://", "https://", "//")) else ep
        except ValueError:
            absolute = ep
        rows.append((absolute, ep, bool(_INTERESTING.search(ep))))
    rows.sort(key=lambda r: (not r[2], r[1].lower()))
    return rows


def scripts_to_fetch(script_srcs: list[str], base_url: str) -> list[str]:
    """External scripts worth downloading: same scope as the page, not images/styles."""
    base_host = (urlparse(base_url).hostname or "").lower()
    out = []
    seen = set()
    for s in script_srcs:
        if not s or s in seen or s.lower().split("?")[0].endswith(_SKIP_EXT):
            continue
        if _same_scope(s, base_host):
            seen.add(s)
            out.append(s)
    return out
