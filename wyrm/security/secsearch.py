"""HackPi Security Search: a search engine for security practitioners.

Classifies the query (CVE, CWE, ATT&CK technique, IP, domain, hash, keyword) and answers it from free,
public, keyless sources, then ranks vulnerabilities by real-world risk rather than CVSS alone:

  1. CISA Known Exploited Vulnerabilities (KEV) catalog - exploited in the wild
  2. EPSS (Jacobs et al., "Exploit Prediction Scoring System", Digital Threats 2021) - 30-day exploit probability
  3. CVSS base score (NVD)
"""
from __future__ import annotations

import ipaddress
import re
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote_plus

import requests

UA = {"User-Agent": "HiddenBrowser/0.3 (HackPi security search)"}
NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
TIMEOUT = 20

_kev_cache: dict = {"t": 0.0, "data": None}


# ------------------------------------------------------------------ classification
def classify(q: str) -> tuple[str, str]:
    s = q.strip()
    if m := re.fullmatch(r"(?i)cve-\d{4}-\d{4,}", s):
        return "cve", s.upper()
    if m := re.fullmatch(r"(?i)cwe-?(\d+)", s):
        return "cwe", m.group(1)
    if re.fullmatch(r"(?i)t\d{4}(\.\d{3})?", s):
        return "attack", s.upper()
    try:
        ipaddress.ip_address(s)
        return "ip", s
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", s):
        return "hash", s.lower()
    if re.fullmatch(r"(?i)(?:\*\.)?(?:[a-z0-9-]+\.)+[a-z]{2,}", s) and " " not in s:
        return "domain", s.lower().lstrip("*.")
    return "keyword", s


# ------------------------------------------------------------------ sources
def kev_catalog() -> dict[str, dict]:
    if _kev_cache["data"] is None or time.time() - _kev_cache["t"] > 6 * 3600:
        r = requests.get(KEV_URL, headers=UA, timeout=30)
        r.raise_for_status()
        _kev_cache["data"] = {v["cveID"]: v for v in r.json().get("vulnerabilities", [])}
        _kev_cache["t"] = time.time()
    return _kev_cache["data"]


def recent_kev(n: int = 6) -> list[dict]:
    """The most recently added CISA Known-Exploited-Vulnerabilities, newest first."""
    rows = sorted(kev_catalog().values(), key=lambda v: v.get("dateAdded", ""), reverse=True)
    return [{"id": v["cveID"], "vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
             "name": v.get("vulnerabilityName", ""), "added": v.get("dateAdded", ""),
             "ransomware": (v.get("knownRansomwareCampaignUse") or "").lower() == "known"} for v in rows[:n]]


def epss(cves: list[str]) -> dict[str, dict]:
    if not cves:
        return {}
    r = requests.get(EPSS_URL, params={"cve": ",".join(cves[:100])}, headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    return {d["cve"]: {"epss": float(d["epss"]), "percentile": float(d["percentile"])} for d in r.json().get("data", [])}


def _nvd(params: dict) -> list[dict]:
    r = requests.get(NVD, params=params, headers=UA, timeout=TIMEOUT)
    if r.status_code in (403, 429):
        raise RuntimeError("NVD rate limit reached; try again in 30 seconds")
    r.raise_for_status()
    out = []
    for item in r.json().get("vulnerabilities", []):
        c = item["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        score, sev, vector = None, "", ""
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = (c.get("metrics") or {}).get(key)
            if m:
                d = m[0]["cvssData"]
                score, vector = d.get("baseScore"), d.get("vectorString", "")
                sev = (d.get("baseSeverity") or m[0].get("baseSeverity") or "").lower()
                break
        cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                       if d.get("value", "").startswith("CWE-")})
        refs = [r["url"] for r in c.get("references", [])][:12]
        out.append({"id": c["id"], "summary": desc, "score": score, "severity": sev, "vector": vector, "cwes": cwes,
                    "published": c.get("published", "")[:10], "refs": refs,
                    "exploit_refs": [r["url"] for r in c.get("references", []) if "Exploit" in (r.get("tags") or [])][:5]})
    return out


def shodan_internetdb(ip: str) -> dict:
    r = requests.get(f"https://internetdb.shodan.io/{ip}", headers=UA, timeout=TIMEOUT)
    if r.status_code == 404:
        return {"ports": [], "vulns": [], "hostnames": [], "tags": [], "cpes": [], "not_found": True}
    r.raise_for_status()
    return r.json()


def _enrich(cves: list[dict], errors: list[str]) -> list[dict]:
    try:
        kev = kev_catalog()
    except Exception as e:  # noqa: BLE001
        kev = {}
        errors.append(f"CISA KEV: {e}")
    try:
        ep = epss([c["id"] for c in cves])
    except Exception as e:  # noqa: BLE001
        ep = {}
        errors.append(f"EPSS: {e}")
    for c in cves:
        c["kev"] = kev.get(c["id"])
        c.update(ep.get(c["id"], {"epss": None, "percentile": None}))
    cves.sort(key=lambda c: (c["kev"] is None, -(c["epss"] or 0), -(c["score"] or 0)))
    return cves


def _kev_matches(q: str, errors: list[str], limit=15) -> list[dict]:
    try:
        kev = kev_catalog()
    except Exception as e:  # noqa: BLE001
        errors.append(f"CISA KEV: {e}")
        return []
    words = [w.lower() for w in re.findall(r"[\w.\-]+", q) if len(w) > 1]
    hits = []
    for v in kev.values():
        hay = f"{v.get('vendorProject')} {v.get('product')} {v.get('vulnerabilityName')}".lower()
        if words and all(w in hay for w in words):
            hits.append(v)
    hits.sort(key=lambda v: v.get("dateAdded", ""), reverse=True)
    return hits[:limit]


# ------------------------------------------------------------------ pivots (one click to the right place)
def pivots(kind: str, value: str) -> list[tuple[str, str]]:
    q = quote_plus(value)
    common_writeups = quote_plus(f'{value} (site:hackerone.com/reports OR site:infosecwriteups.com OR site:portswigger.net/research OR site:medium.com)')
    if kind == "cve":
        return [("NVD", f"https://nvd.nist.gov/vuln/detail/{value}"), ("MITRE CVE", f"https://www.cve.org/CVERecord?id={value}"),
                ("PoC on GitHub", f"https://github.com/search?q={q}&type=repositories&s=updated"),
                ("Exploit-DB", f"https://www.exploit-db.com/search?cve={value.replace('CVE-', '')}"),
                ("GitHub advisories", f"https://github.com/advisories?query={q}"),
                ("Vulners", f"https://vulners.com/search?query={q}"),
                ("Nuclei templates", f"https://github.com/search?q=repo%3Aprojectdiscovery%2Fnuclei-templates+{q}&type=code"),
                ("Write-ups", f"https://www.google.com/search?q={common_writeups}")]
    if kind == "ip":
        return [("Shodan", f"https://www.shodan.io/host/{value}"), ("Censys", f"https://search.censys.io/hosts/{value}"),
                ("AbuseIPDB", f"https://www.abuseipdb.com/check/{value}"), ("GreyNoise", f"https://viz.greynoise.io/ip/{value}"),
                ("VirusTotal", f"https://www.virustotal.com/gui/ip-address/{value}"), ("BGP / ASN", f"https://bgp.he.net/ip/{value}")]
    if kind == "domain":
        return [("crt.sh subdomains", f"https://crt.sh/?q=%25.{value}"), ("Wayback URLs", f"https://web.archive.org/web/*/{value}/*"),
                ("Shodan", f"https://www.shodan.io/search?query=hostname%3A{value}"),
                ("urlscan.io", f"https://urlscan.io/search/#domain%3A{value}"),
                ("VirusTotal", f"https://www.virustotal.com/gui/domain/{value}"),
                ("DNS records", f"https://dnsdumpster.com/"), ("security.txt", f"https://{value}/.well-known/security.txt"),
                ("Bug bounty program?", f"https://www.google.com/search?q={quote_plus(value + ' bug bounty OR vulnerability disclosure program')}")]
    if kind == "hash":
        return [("VirusTotal", f"https://www.virustotal.com/gui/file/{value}"),
                ("MalwareBazaar", f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{value}" if len(value) == 64
                 else f"https://bazaar.abuse.ch/browse.php?search={value}"),
                ("Hybrid Analysis", f"https://www.hybrid-analysis.com/search?query={value}"),
                ("Google", f"https://www.google.com/search?q={q}")]
    if kind == "cwe":
        return [("MITRE CWE", f"https://cwe.mitre.org/data/definitions/{value}.html"),
                ("OWASP", f"https://www.google.com/search?q={quote_plus('CWE-' + value + ' site:owasp.org')}"),
                ("PortSwigger", f"https://www.google.com/search?q={quote_plus('CWE-' + value + ' site:portswigger.net')}")]
    if kind == "attack":
        tid = value.replace(".", "/")
        return [("MITRE ATT&CK", f"https://attack.mitre.org/techniques/{tid}/"),
                ("Atomic Red Team", f"https://github.com/redcanaryco/atomic-red-team/tree/master/atomics/{value}"),
                ("Sigma rules", f"https://github.com/search?q=repo%3ASigmaHQ%2Fsigma+{q}&type=code")]
    return [("Write-ups", f"https://www.google.com/search?q={common_writeups}"),
            ("PoC on GitHub", f"https://github.com/search?q={quote_plus(value + ' exploit OR poc')}&type=repositories&s=updated"),
            ("Exploit-DB", f"https://www.exploit-db.com/search?q={q}"),
            ("GitHub advisories", f"https://github.com/advisories?query={q}"),
            ("PortSwigger", f"https://www.google.com/search?q={quote_plus(value + ' site:portswigger.net')}"),
            ("HackTricks", f"https://www.google.com/search?q={quote_plus(value + ' site:book.hacktricks.wiki')}"),
            ("OWASP", f"https://www.google.com/search?q={quote_plus(value + ' site:owasp.org')}"),
            ("r/netsec", f"https://www.reddit.com/r/netsec/search/?q={q}"),
            ("Web (DuckDuckGo)", f"https://duckduckgo.com/?q={q}")]


# ------------------------------------------------------------------ main entry
def search(query: str) -> dict:
    kind, value = classify(query)
    errors: list[str] = []
    out = {"query": query, "kind": kind, "value": value, "errors": errors, "pivots": pivots(kind, value),
           "cves": [], "kev": [], "card": None}
    if kind == "cve":
        try:
            out["cves"] = _enrich(_nvd({"cveId": value}), errors)
        except Exception as e:  # noqa: BLE001
            errors.append(f"NVD: {e}")
            out["cves"] = _enrich([{"id": value, "summary": "", "score": None, "severity": "", "vector": "", "cwes": [],
                                    "published": "", "refs": [], "exploit_refs": []}], errors)
    elif kind == "ip":
        try:
            db = shodan_internetdb(value)
            out["card"] = {"type": "ip", **db}
            if db.get("vulns"):
                out["cves"] = _enrich([{"id": v, "summary": "", "score": None, "severity": "", "vector": "", "cwes": [],
                                        "published": "", "refs": [], "exploit_refs": []} for v in db["vulns"][:60]], errors)
        except Exception as e:  # noqa: BLE001
            errors.append(f"Shodan InternetDB: {e}")
    elif kind == "cwe":
        try:
            out["cves"] = _enrich(_nvd({"cweId": f"CWE-{value}", "resultsPerPage": 40,
                                        "cvssV3Severity": "CRITICAL"}), errors)
        except Exception as e:  # noqa: BLE001
            errors.append(f"NVD: {e}")
    elif kind == "keyword":
        with ThreadPoolExecutor(2) as pool:
            f_nvd = pool.submit(_nvd, {"keywordSearch": value, "resultsPerPage": 40})
            f_kev = pool.submit(_kev_matches, value, errors)
            try:
                cves = f_nvd.result()
            except Exception as e:  # noqa: BLE001
                errors.append(f"NVD: {e}")
                cves = []
            out["kev"] = f_kev.result()
        out["cves"] = _enrich(cves, errors)
    # domain / hash / attack: answer card is the pivots themselves (no keyless API worth calling)
    out["card"] = out["card"] or {"type": kind}
    return out
