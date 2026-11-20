"""Threat intel + recon from public, passive sources.

CVEs:  OSV.dev (exact package+version for JS libraries) and NVD (keyword search for servers/CMS).
Recon: crt.sh certificate transparency (subdomains), Wayback Machine CDX (historic URLs),
       robots.txt / sitemap.xml / security.txt of the target.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET

import requests

UA = {"User-Agent": "HiddenBrowser/0.2 (security testing browser)"}
TIMEOUT = 20


# ------------------------------------------------------------------ CVEs
def cves_osv(npm_name: str, version: str) -> list[dict]:
    r = requests.post("https://api.osv.dev/v1/query", json={"package": {"name": npm_name, "ecosystem": "npm"},
                                                             "version": version}, headers=UA, timeout=TIMEOUT)
    r.raise_for_status()
    out = []
    for v in r.json().get("vulns", []):
        aliases = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
        sev = (v.get("database_specific") or {}).get("severity", "")
        out.append({"id": aliases[0] if aliases else v["id"], "ghsa": v["id"], "summary": v.get("summary") or v.get("details", "")[:200],
                    "severity": sev.lower(), "url": f"https://osv.dev/vulnerability/{v['id']}"})
    return out


CPE_PRODUCT = {"apache": "http_server", "httpd": "http_server", "microsoft-iis": "internet_information_services",
               "iis": "internet_information_services", "php": "php", "openssl": "openssl", "nginx": "nginx",
               "wordpress": "wordpress", "drupal": "drupal", "joomla!": "joomla\\!", "express": "express",
               "tomcat": "tomcat", "apache-coyote": "tomcat", "lighttpd": "lighttpd", "openresty": "openresty"}


def cves_nvd(product: str, version: str) -> list[dict]:
    # CPE "virtual match" understands version ranges, unlike keyword search
    cpe_product = CPE_PRODUCT.get(product.lower(), re.sub(r"[^a-z0-9_]", "_", product.lower()))
    r = requests.get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                     params={"virtualMatchString": f"cpe:2.3:a:*:{cpe_product}:{version}", "resultsPerPage": 50},
                     headers=UA, timeout=TIMEOUT)
    if r.status_code in (403, 429):
        raise RuntimeError("NVD rate limit hit; wait 30 seconds and retry")
    r.raise_for_status()
    out = []
    for item in r.json().get("vulnerabilities", []):
        c = item["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        score, sev = None, ""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            m = (c.get("metrics") or {}).get(key)
            if m:
                score = m[0]["cvssData"].get("baseScore")
                sev = (m[0]["cvssData"].get("baseSeverity") or m[0].get("baseSeverity") or "").lower()
                break
        out.append({"id": c["id"], "summary": desc[:300], "severity": sev, "score": score,
                    "url": f"https://nvd.nist.gov/vuln/detail/{c['id']}"})
    out.sort(key=lambda x: -(x.get("score") or 0))
    return out


def lookup_cves(tech: dict) -> list[dict]:
    if not tech.get("version"):
        raise RuntimeError("Version unknown; can't match CVEs reliably")
    if tech.get("npm"):
        return cves_osv(tech["npm"], tech["version"])
    return cves_nvd(tech["name"], tech["version"])


# ------------------------------------------------------------------ recon
def subdomains_crtsh(domain: str) -> list[str]:
    r = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"}, headers=UA, timeout=45)
    r.raise_for_status()
    names = set()
    for row in r.json():
        for n in row.get("name_value", "").splitlines():
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain) and " " not in n:
                names.add(n)
    return sorted(names, key=lambda n: (n.count("."), n))


def wayback_urls(domain: str, limit: int = 2000) -> list[dict]:
    r = requests.get("https://web.archive.org/cdx/search/cdx",
                     params={"url": f"{domain}/*", "output": "json", "fl": "original,statuscode,mimetype,timestamp",
                             "collapse": "urlkey", "limit": limit}, headers=UA, timeout=60)
    r.raise_for_status()
    rows = r.json()
    return [dict(zip(rows[0], row)) for row in rows[1:]] if rows else []


INTERESTING_URL = re.compile(r"\.(bak|old|sql|zip|tar|gz|env|log|conf|config|ini|ya?ml|json|xml|txt|php|aspx?|jsp)(\?|$)|"
                             r"admin|debug|backup|internal|api|token|redirect=|url=|next=|callback=", re.I)


def well_known(base: str) -> dict:
    """robots.txt, sitemap.xml, security.txt for an origin like https://example.com."""
    base = base.rstrip("/")
    out = {}
    for name, path in (("robots.txt", "/robots.txt"), ("security.txt", "/.well-known/security.txt"),
                       ("sitemap.xml", "/sitemap.xml")):
        try:
            r = requests.get(base + path, headers=UA, timeout=TIMEOUT)
            ok = r.ok and "<html" not in r.text[:500].lower()
            out[name] = {"status": r.status_code, "text": r.text[:200000] if ok else "", "found": ok}
        except requests.RequestException as e:
            out[name] = {"status": None, "text": "", "found": False, "error": str(e)}
    robots = out["robots.txt"]["text"]
    out["disallowed"] = [base + p.split(":", 1)[1].strip() for p in robots.splitlines()
                         if p.lower().startswith("disallow:") and p.split(":", 1)[1].strip() not in ("", "/")]
    sm = out["sitemap.xml"]["text"]
    urls = []
    if sm:
        try:
            urls = [e.text.strip() for e in ET.fromstring(sm.encode()).iter() if e.tag.endswith("loc") and e.text][:1000]
        except ET.ParseError:
            pass
    out["sitemap_urls"] = urls
    return out
