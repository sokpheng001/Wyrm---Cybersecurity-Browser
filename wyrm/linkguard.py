#------------------------------------------------------------------------------
# Wyrm — wyrm/linkguard.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Smart link detection: scores any URL for phishing / malicious traits before you open it.

Two layers:
  1. Threat intelligence: the Shields engines (URLhaus malware, phishing-filter from OpenPhish/PhishTank data,
     uBlock badware). A hit is always "dangerous".
  2. Heuristics drawn from URL-based phishing research (e.g. Sahingoz et al., "Machine learning based phishing
     detection from URLs", Expert Systems with Applications 2019): brand impersonation, typosquatting,
     IDN homographs, userinfo tricks, raw IPs, risky TLDs, shorteners, deep subdomains, credential keywords.
Also: tracking-parameter stripping and private-network detection used by HTTPS-Only mode.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

BRANDS = {
    "paypal": "paypal.com", "google": "google.com", "gmail": "google.com", "apple": "apple.com", "icloud": "icloud.com",
    "microsoft": "microsoft.com", "office365": "office.com", "outlook": "outlook.com", "live": "live.com",
    "amazon": "amazon.com", "facebook": "facebook.com", "instagram": "instagram.com", "whatsapp": "whatsapp.com",
    "netflix": "netflix.com", "linkedin": "linkedin.com", "github": "github.com", "dropbox": "dropbox.com",
    "docusign": "docusign.com", "adobe": "adobe.com", "yahoo": "yahoo.com", "twitter": "twitter.com",
    "coinbase": "coinbase.com", "binance": "binance.com", "metamask": "metamask.io", "blockchain": "blockchain.com",
    "steam": "steampowered.com", "steamcommunity": "steamcommunity.com", "roblox": "roblox.com",
    "chase": "chase.com", "wellsfargo": "wellsfargo.com", "bankofamerica": "bankofamerica.com", "citibank": "citi.com",
    "hsbc": "hsbc.com", "dhl": "dhl.com", "fedex": "fedex.com", "usps": "usps.com", "ups": "ups.com",
    "naver": "naver.com", "kakao": "kakao.com", "telegram": "telegram.org", "discord": "discord.com",
}
OFFICIAL_ALSO = {"google": {"youtube.com", "googleusercontent.com", "gstatic.com", "google.co.kr", "googleapis.com"},
                 "microsoft": {"live.com", "office.com", "microsoftonline.com", "azure.com", "bing.com", "windows.net"},
                 "apple": {"icloud.com"}, "amazon": {"amazonaws.com", "amazon.co.uk", "amazon.co.jp", "amazon.de"},
                 "facebook": {"fb.com", "facebook.net", "fbcdn.net", "meta.com"}, "live": {"microsoft.com", "outlook.com"},
                 "kakao": {"kakaocorp.com", "daum.net"}}
RISKY_TLDS = {"zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "rest", "fit",
              "support", "icu", "cyou", "buzz", "monster", "sbs", "quest", "cfd", "lol", "bond", "beauty", "hair"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rebrand.ly", "cutt.ly", "rb.gy",
              "shorturl.at", "s.id", "t.ly", "tiny.cc", "lnkd.in", "qrco.de", "bit.do"}
# Common two-level public suffixes (so e.g. cadt.edu.kh is kept whole, not collapsed to edu.kh).
# A pragmatic subset of the Mozilla Public Suffix List covering the most-hit ccSLDs.
_SLD = ("com net org edu gov mil ac co or ne go re pe biz info name int")  # second-level labels…
_CCTLD = ("kh uk au jp kr cn tw in nz sg mx br za tr vn id th il sa ph pk bd np lk ke ng gh my hk "
          "ua ar cl pe ve ru pl ro gr es it fr nl be se no fi dk pt cz hu")  # …under these ccTLDs
MULTI_SUFFIX = {f"{s}.{c}" for c in _CCTLD.split() for s in _SLD.split()} | {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",  # UK specials
    "com.kh", "edu.kh", "gov.kh", "net.kh", "org.kh", "mil.kh", "per.kh",
}
CRED_WORDS = re.compile(r"log-?in|sign-?in|verify|verification|account|update|secure|wallet|password|passwd|banking|"
                        r"unlock|suspend|confirm|billing|invoice|recover|seed|2fa|otp", re.I)
TRACKING_PARAMS = re.compile(r"^(utm_[a-z_]+|fbclid|gclid|gclsrc|dclid|gbraid|wbraid|msclkid|mc_eid|mc_cid|igshid|"
                             r"yclid|_hsenc|_hsmi|mkt_tok|oly_anon_id|oly_enc_id|vero_id|ttclid|twclid|li_fat_id|"
                             r"s_cid|ref_src|__s|ssp_iabi|rb_clickid|epik)$", re.I)


def registered_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in MULTI_SUFFIX:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def is_private_host(host: str) -> bool:
    h = (host or "").lower().strip("[]")
    if h in ("localhost",) or "." not in h or h.endswith((".local", ".lan", ".internal", ".test", ".localhost", ".home.arpa")):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def _lev(a: str, b: str, cap: int = 3) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "4": "a", "@": "a", "$": "s",
                            # Cyrillic / Greek letters that render like Latin ones (IDN homograph attacks)
                            "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
                            "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ո": "n", "ѕ": "s", "ԝ": "w", "α": "a", "ο": "o",
                            "ρ": "p", "ν": "v", "κ": "k", "τ": "t"})


def analyze(url: str, threat: str | None = None) -> dict:
    """Return {'score': 0-100, 'verdict': 'safe'|'suspicious'|'dangerous', 'reasons': [...], 'host': ...}."""
    reasons: list[tuple[int, str]] = []
    try:
        p = urlsplit(url)
    except ValueError:
        return {"score": 50, "verdict": "suspicious", "reasons": ["Malformed link"], "host": ""}
    scheme = p.scheme.lower()
    if scheme in ("javascript", "vbscript"):
        return {"score": 60, "verdict": "suspicious", "reasons": ["Runs script instead of opening a page"], "host": ""}
    if scheme == "data":
        return {"score": 75, "verdict": "dangerous", "reasons": ["data: link can contain a fake page (common phishing trick)"], "host": ""}
    if scheme not in ("http", "https"):
        return {"score": 0, "verdict": "safe", "reasons": [], "host": ""}
    host = (p.hostname or "").lower()
    if threat:
        label = {"malware": "Listed as a malware distribution site (URLhaus / badware lists)",
                 "phishing": "Listed as a phishing site (phishing-filter / OpenPhish / PhishTank data)"}.get(threat, threat)
        return {"score": 100, "verdict": "dangerous", "reasons": [label], "host": host}
    if is_private_host(host):
        return {"score": 0, "verdict": "safe", "reasons": [], "host": host}
    reg = registered_domain(host)
    label = reg.split(".")[0]
    sub = host[: -len(reg)].rstrip(".") if host != reg else ""
    tld = host.rsplit(".", 1)[-1]

    if "@" in p.netloc:
        reasons.append((35, f"Text before '@' hides the real destination: {host}"))
    try:
        ipaddress.ip_address(host)
        reasons.append((25, "Uses a raw IP address instead of a domain name"))
    except ValueError:
        pass
    if "xn--" in host:
        try:
            shown = host.encode().decode("idna")
        except UnicodeError:
            shown = host
        reasons.append((25, f"Uses international characters (shown as '{shown}'): check it isn't a look-alike"))
        reg_u = registered_domain(shown)
        label, sub = reg_u.split(".")[0], shown[: -len(reg_u)].rstrip(".")  # compare brands on what the user SEES
    norm = label.translate(HOMOGLYPHS).replace("-", "")
    for brand, official in BRANDS.items():
        allowed = {official} | OFFICIAL_ALSO.get(brand, set())
        if reg in allowed:
            break
        in_name = brand in (sub + "." + label).replace("-", "").translate(HOMOGLYPHS) if len(brand) >= 4 else \
            brand in sub.split(".") or label == brand
        if in_name:
            reasons.append((45, f"Mentions '{brand}' but the site is {reg}, not {official}"))
            break
        if len(brand) >= 5 and 0 < _lev(norm, brand) <= (1 if len(brand) < 7 else 2):
            reasons.append((45, f"Looks like {official} but is {reg} (typosquatting)"))
            break
    if tld in RISKY_TLDS:
        reasons.append((15, f"Domain ending .{tld} is heavily used for abuse"))
    if reg in SHORTENERS:
        reasons.append((12, "Shortened link: the real destination is hidden"))
    if sub.count(".") >= 3:
        reasons.append((10, "Unusually deep subdomain chain"))
    if label.count("-") >= 3 and "xn--" not in host:
        reasons.append((10, "Many hyphens in the domain name"))
    if len(url) > 160:
        reasons.append((5, "Very long URL"))
    cred = CRED_WORDS.search(host + p.path)
    if cred and reasons:
        reasons.append((10, f"Asks for credentials ('{cred.group(0)}') on a site with other red flags"))
    if scheme == "http" and cred:
        reasons.append((15, "Login-style page without encryption (HTTP)"))
    score = min(100, sum(w for w, _ in reasons))
    verdict = "dangerous" if score >= 70 else "suspicious" if score >= 35 else "safe"
    return {"score": score, "verdict": verdict, "reasons": [r for _, r in sorted(reasons, reverse=True)], "host": host}


def strip_tracking(url: str) -> str:
    """Remove click-tracking parameters (utm_*, fbclid, gclid, …). Returns the same URL if nothing changes."""
    try:
        p = urlsplit(url)
    except ValueError:
        return url
    if not p.query:
        return url
    q = parse_qsl(p.query, keep_blank_values=True)
    kept = [(k, v) for k, v in q if not TRACKING_PARAMS.match(k)]
    if len(kept) == len(q):
        return url
    return urlunsplit((p.scheme, p.netloc, p.path, urlencode(kept, doseq=True), p.fragment))


BEACON = re.compile(r"/(pixel|beacon|collect|track(ing)?|analytics|telemetry|impression|imp|pageview|event)s?"
                    r"(\.gif|\.png|\.php|/|\?|$)", re.I)


def heuristic_tracker(url: str, first_party_host: str, rtype: str) -> bool:
    """HackPi's own rule: third-party beacons the filter lists miss (images/pings/xhr hitting tracking endpoints)."""
    if rtype not in ("Image", "Ping", "Xhr", "CspReport"):
        return False
    try:
        p = urlsplit(url)
    except ValueError:
        return False
    host = p.hostname or ""
    if not host or not first_party_host or registered_domain(host) == registered_domain(first_party_host):
        return False
    if rtype == "Ping":
        return True  # <a ping> / sendBeacon to a third party is tracking by definition
    return bool(BEACON.search(p.path)) and bool(re.search(r"(uid|cid|sid|vid|uuid|client_?id|user_?id)=", p.query, re.I))
