#------------------------------------------------------------------------------
# Wyrm — wyrm/security/tools.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Tester's toolbox: encoders/decoders, JWT inspector, hash identify/compute, HTTP repeater."""
from __future__ import annotations

import base64
import binascii
import hashlib
import html
import json
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote, unquote

import requests


def _b64d(s: str) -> str:
    s = s.strip()
    s += "=" * (-len(s) % 4)
    raw = base64.urlsafe_b64decode(s.replace("+", "-").replace("/", "_"))
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return "hex: " + raw.hex()


TRANSFORMS = {
    "Base64 encode": lambda s: base64.b64encode(s.encode()).decode(),
    "Base64 decode": _b64d,
    "URL encode": lambda s: quote(s, safe=""),
    "URL decode": unquote,
    "Double URL encode": lambda s: quote(quote(s, safe=""), safe=""),
    "HTML entity encode": lambda s: html.escape(s, quote=True),
    "HTML entity decode": html.unescape,
    "Hex encode": lambda s: s.encode().hex(),
    "Hex decode": lambda s: bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", s)).decode("utf-8", "replace"),
    "Unicode escape (\\uXXXX)": lambda s: "".join(f"\\u{ord(c):04x}" for c in s),
    "Unicode unescape": lambda s: s.encode().decode("unicode_escape"),
    "JS string.fromCharCode": lambda s: "String.fromCharCode(" + ",".join(str(ord(c)) for c in s) + ")",
    "ROT13": lambda s: s.translate(str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                                                 "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm")),
    "Uppercase": str.upper,
    "Lowercase": str.lower,
    "Reverse": lambda s: s[::-1],
}


def transform(name: str, s: str) -> str:
    try:
        return TRANSFORMS[name](s)
    except (binascii.Error, ValueError, UnicodeDecodeError) as e:
        return f"[error] {e}"


def smart_decode(s: str, max_steps: int = 6) -> list[tuple[str, str]]:
    """Repeatedly apply the decoder that seems to fit (URL → Base64 → HTML → hex)."""
    steps, cur = [], s.strip()
    for _ in range(max_steps):
        nxt = None
        if re.search(r"%[0-9a-fA-F]{2}", cur):
            nxt = ("URL decode", unquote(cur))
        elif re.fullmatch(r"(?:[A-Za-z0-9+/_\-]{4})+(?:[A-Za-z0-9+/_\-]{2,3}=?=?)?", cur) and len(cur) >= 8:
            d = _b64d(cur)
            if not d.startswith("hex:") and d.isprintable():
                nxt = ("Base64 decode", d)
        elif re.search(r"&(#\d+|#x[0-9a-f]+|[a-z]+);", cur, re.I):
            nxt = ("HTML entity decode", html.unescape(cur))
        elif re.fullmatch(r"(?:[0-9a-fA-F]{2})+", cur) and len(cur) >= 8:
            try:
                nxt = ("Hex decode", bytes.fromhex(cur).decode("utf-8"))
            except UnicodeDecodeError:
                pass
        if not nxt or nxt[1] == cur:
            break
        steps.append(nxt)
        cur = nxt[1]
    return steps


# ------------------------------------------------------------------ JWT
def decode_jwt(token: str) -> dict:
    parts = token.strip().split(".")
    if len(parts) < 2:
        raise ValueError("Not a JWT (expected header.payload.signature)")
    header = json.loads(_b64d(parts[0]))
    payload = json.loads(_b64d(parts[1]))
    notes = []
    alg = str(header.get("alg", "")).lower()
    if alg == "none":
        notes.append("⚠ alg is 'none': if the server accepts this token, signatures aren't checked.")
    if alg.startswith("hs"):
        notes.append("HMAC-signed: if the secret is weak it can be brute-forced offline; test against a wordlist only if in scope.")
    if "kid" in header:
        notes.append("Has 'kid' header: check it isn't used unsafely (path traversal / SQL) by the server.")
    if "jku" in header or "x5u" in header:
        notes.append("Has jku/x5u: check the server doesn't fetch keys from attacker-controlled URLs.")
    now = datetime.now(timezone.utc).timestamp()
    for k in ("iat", "nbf", "exp"):
        if isinstance(payload.get(k), (int, float)):
            payload[f"{k} (UTC)"] = datetime.fromtimestamp(payload[k], timezone.utc).isoformat()
    if isinstance(payload.get("exp"), (int, float)):
        notes.append("Token is EXPIRED." if payload["exp"] < now else
                     f"Expires in {int((payload['exp'] - now) / 60)} minutes.")
    else:
        notes.append("No 'exp' claim: token never expires.")
    return {"header": header, "payload": payload, "signature_present": len(parts) > 2 and bool(parts[2]), "notes": notes}


# ------------------------------------------------------------------ hashes
def identify_hash(h: str) -> list[str]:
    h = h.strip()
    if re.match(r"^\$2[abxy]?\$\d{2}\$", h):
        return ["bcrypt"]
    if h.startswith("$argon2"):
        return ["Argon2"]
    if h.startswith("$6$"):
        return ["SHA-512 crypt (Linux shadow)"]
    if h.startswith("$5$"):
        return ["SHA-256 crypt"]
    if h.startswith("$1$"):
        return ["MD5 crypt"]
    if h.startswith("pbkdf2_sha256$"):
        return ["Django PBKDF2-SHA256"]
    if re.fullmatch(r"[0-9a-fA-F]+", h):
        return {32: ["MD5", "NTLM", "MD4"], 40: ["SHA-1", "RIPEMD-160"], 56: ["SHA-224", "SHA3-224"],
                64: ["SHA-256", "SHA3-256"], 96: ["SHA-384", "SHA3-384"], 128: ["SHA-512", "SHA3-512", "Whirlpool"],
                16: ["MySQL323", "CRC-64"], 8: ["CRC-32", "Adler-32"]}.get(len(h), ["Unknown hex digest"])
    if re.fullmatch(r"[A-Za-z0-9+/]{27}=|[A-Za-z0-9+/]{43}=|[A-Za-z0-9+/]{86}==", h):
        return ["Base64-encoded digest (SHA-1 / SHA-256 / SHA-512)"]
    return ["Unknown format"]


def compute_hashes(s: str) -> dict[str, str]:
    b = s.encode()
    return {n: hashlib.new(n, b).hexdigest() for n in ("md5", "sha1", "sha256", "sha512")}


# ------------------------------------------------------------------ repeater
def parse_headers(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def send_request(method: str, url: str, headers_text: str, body: str, proxies=None, verify=True,
                 follow_redirects=False) -> dict:
    t = time.perf_counter()
    r = requests.request(method, url, headers=parse_headers(headers_text), data=body.encode() if body else None,
                         timeout=30, proxies=proxies, verify=verify, allow_redirects=follow_redirects)
    ms = int((time.perf_counter() - t) * 1000)
    ctype = r.headers.get("content-type", "")
    text = r.text[:300000] if ("text" in ctype or "json" in ctype or "xml" in ctype or "javascript" in ctype or not ctype) \
        else f"[{len(r.content)} bytes of {ctype}]"
    if "json" in ctype:
        try:
            text = json.dumps(r.json(), indent=2)[:300000]
        except ValueError:
            pass
    head = f"HTTP {r.status_code} {r.reason}  ·  {ms} ms  ·  {len(r.content)} bytes\n" + \
           "\n".join(f"{k}: {v}" for k, v in r.headers.items())
    return {"status": r.status_code, "head": head, "body": text}


def to_curl(method: str, url: str, headers: dict | None = None, body: str | None = None) -> str:
    q = lambda s: "'" + s.replace("'", "'\\''") + "'"  # noqa: E731
    parts = ["curl", "-i"]
    if method and method.upper() != "GET":
        parts += ["-X", method.upper()]
    for k, v in (headers or {}).items():
        parts += ["-H", q(f"{k}: {v}")]
    if body:
        parts += ["--data-raw", q(body)]
    parts.append(q(url))
    return " ".join(parts)


# ------------------------------------------------------------------ Comparer (diff two payloads)
def word_diff(a: str, b: str) -> list[tuple[str, str]]:
    """Word/token-level diff. Returns [(op, text)] where op is 'equal' | 'insert' | 'delete' | 'replace'."""
    import difflib
    ta = re.split(r"(\s+)", a)
    tb = re.split(r"(\s+)", b)
    sm = difflib.SequenceMatcher(None, ta, tb, autojunk=False)
    out = []
    for op, i1, i2, j1, j2 in sm.get_opcodes():
        if op == "equal":
            out.append(("equal", "".join(ta[i1:i2])))
        elif op == "delete":
            out.append(("delete", "".join(ta[i1:i2])))
        elif op == "insert":
            out.append(("insert", "".join(tb[j1:j2])))
        else:  # replace
            out.append(("delete", "".join(ta[i1:i2])))
            out.append(("insert", "".join(tb[j1:j2])))
    return out


def diff_stats(a: str, b: str) -> dict:
    import difflib
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return {"ratio": round(sm.ratio() * 100, 1), "len_a": len(a), "len_b": len(b)}


# ------------------------------------------------------------------ Sequencer (token randomness)
def analyze_tokens(tokens: list[str]) -> dict:
    """Estimate the randomness/predictability of a set of session/CSRF/reset tokens.

    Reports Shannon entropy per character position and overall, the effective character set, length
    consistency, duplicate rate, and a plain verdict. Analysis only — nothing is sent anywhere.
    """
    import math
    from collections import Counter

    toks = [t.strip() for t in tokens if t.strip()]
    n = len(toks)
    if n < 2:
        return {"error": "Paste at least 2 tokens (one per line)."}
    lengths = Counter(len(t) for t in toks)
    common_len, _ = lengths.most_common(1)[0]
    same_len = [t for t in toks if len(t) == common_len]
    uniq = len(set(toks))

    def shannon(counter: Counter, total: int) -> float:
        return -sum((c / total) * math.log2(c / total) for c in counter.values() if c)

    # per-position entropy over tokens that share the most common length
    pos_entropy = []
    charset = set()
    for i in range(common_len):
        col = Counter(t[i] for t in same_len)
        charset |= set(col)
        pos_entropy.append(round(shannon(col, len(same_len)), 2))
    total_bits = round(sum(pos_entropy), 1)
    max_bits = round(common_len * math.log2(max(2, len(charset))), 1)
    quality = (total_bits / max_bits) if max_bits else 0
    verdict = ("Strong — looks random" if quality >= 0.85 and total_bits >= 64 else
               "Adequate" if quality >= 0.6 and total_bits >= 40 else
               "Weak — low entropy / predictable")
    return {
        "count": n, "unique": uniq, "duplicates": n - uniq,
        "common_length": common_len, "length_consistent": len(lengths) == 1,
        "charset_size": len(charset),
        "charset_sample": "".join(sorted(charset)[:60]),
        "entropy_bits": total_bits, "max_bits": max_bits, "quality_pct": round(quality * 100),
        "pos_entropy": pos_entropy, "verdict": verdict,
    }
