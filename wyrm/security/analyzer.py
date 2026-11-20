"""Passive security analysis of a page: headers, CSP, cookies, TLS, page content, technologies, JS.

Everything here is read-only: one ordinary GET of the page you are already viewing (to see response
headers the browser engine doesn't expose), a TLS handshake to read the certificate, and the
JavaScript files the page already loads. No payloads, no fuzzing.
"""
from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HiddenBrowser/0.2"
TIMEOUT = 12
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def issue(category, title, severity, detail="", evidence="", **extra) -> dict:
    return {"category": category, "title": title, "severity": severity, "detail": detail, "evidence": evidence, **extra}


# ------------------------------------------------------------------ network fetches
def fetch_response(url: str, proxies=None, verify=True) -> dict:
    r = requests.get(url, headers={"User-Agent": UA}, timeout=TIMEOUT, allow_redirects=True, stream=True,
                     proxies=proxies, verify=verify)
    try:
        raw = r.raw.headers
        cookies = raw.getlist("Set-Cookie") if hasattr(raw, "getlist") else []
        return {"status": r.status_code, "url": r.url, "headers": {k.lower(): v for k, v in r.headers.items()},
                "set_cookies": cookies, "redirects": [h.url for h in r.history]}
    finally:
        r.close()


def fetch_tls(host: str, port: int = 443) -> dict:
    info = {"host": host, "port": port}
    ctx = ssl.create_default_context()  # system store (keeps corporate/proxy CAs working)…
    try:
        import certifi  # …plus Mozilla's bundle, so missing intermediates/roots on Windows aren't false alarms
        ctx.load_verify_locations(certifi.where())
    except (ImportError, OSError):
        pass
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                info.update(valid=True, version=s.version(), cipher=s.cipher()[0])
    except ssl.SSLCertVerificationError as e:
        info.update(valid=False, error=e.verify_message or str(e))
        cert = None
    except Exception as e:  # noqa: BLE001
        info.update(valid=None, error=str(e))
        cert = None
    if cert:
        get = lambda k: dict(x[0] for x in cert.get(k, ()))  # noqa: E731
        info["subject"] = get("subject").get("commonName", "")
        info["issuer"] = get("issuer").get("organizationName") or get("issuer").get("commonName", "")
        info["not_after"] = cert.get("notAfter")
        info["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:50]
        try:
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            info["days_left"] = (exp - datetime.now(timezone.utc)).days
        except (KeyError, ValueError):
            pass
    return info


# ------------------------------------------------------------------ CSP (Weichselbaum et al., CCS 2016)
# Hosts known to serve JSONP endpoints or old AngularJS, which defeat host allowlists in script-src.
BYPASSABLE_HOSTS = ["*.googleapis.com", "ajax.googleapis.com", "*.google.com", "www.google.com", "cdnjs.cloudflare.com",
                    "cdn.jsdelivr.net", "unpkg.com", "*.gstatic.com", "accounts.google.com", "*.yandex.ru",
                    "*.facebook.com", "*.twitter.com", "raw.githubusercontent.com", "*.amazonaws.com"]


def parse_csp(value: str) -> dict[str, list[str]]:
    out = {}
    for part in value.split(";"):
        bits = part.strip().split()
        if bits:
            out.setdefault(bits[0].lower(), [b for b in bits[1:]])
    return out


def evaluate_csp(value: str | None, report_only: str | None) -> list[dict]:
    C = "Content-Security-Policy"
    if not value:
        out = [issue(C, "No Content-Security-Policy", "medium",
                     "Without a CSP, any XSS bug can run arbitrary script. Recommended: a nonce-based "
                     "'strict-dynamic' policy, plus object-src 'none' and base-uri 'none'.")]
        if report_only:
            out.append(issue(C, "CSP is report-only (not enforced)", "info", evidence=report_only[:500]))
        return out
    d = parse_csp(value)
    script = d.get("script-src", d.get("default-src"))
    out = []
    if script is None:
        out.append(issue(C, "CSP has no script-src or default-src", "high",
                         "Scripts are unrestricted, so the policy does not mitigate XSS.", value[:500]))
    else:
        s = [x.lower() for x in script]
        has_nonce_hash = any(x.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for x in s)
        strict_dynamic = "'strict-dynamic'" in s
        if "'unsafe-inline'" in s and not has_nonce_hash:
            out.append(issue(C, "script-src allows 'unsafe-inline'", "high",
                             "Inline scripts and event handlers run, so reflected/stored XSS is not mitigated."))
        if "'unsafe-eval'" in s:
            out.append(issue(C, "script-src allows 'unsafe-eval'", "medium",
                             "eval()/new Function() are allowed; DOM-XSS gadgets become exploitable."))
        if "*" in s or any(x in s for x in ("http:", "https:", "data:")):
            bad = [x for x in s if x in ("*", "http:", "https:", "data:")]
            out.append(issue(C, f"script-src allows broad sources: {' '.join(bad)}", "high",
                             "Script can be loaded from any host or a data: URL, which defeats the policy."))
        hosts = [x for x in s if not x.startswith("'") and x not in ("*", "http:", "https:", "data:", "blob:")]
        if hosts and not strict_dynamic:
            risky = [h for h in hosts if any(h == b or h.endswith(b.lstrip("*")) for b in BYPASSABLE_HOSTS)]
            sev = "medium" if risky else "low"
            out.append(issue(C, "script-src relies on a host allowlist", sev,
                             "Weichselbaum et al. (CCS 2016) found that most host allowlists can be bypassed through "
                             "JSONP endpoints or old AngularJS on an allowed host. Prefer nonces + 'strict-dynamic'."
                             + (f" Known-bypassable hosts here: {', '.join(risky)}." if risky else ""),
                             " ".join(hosts)[:500]))
    obj = d.get("object-src", d.get("default-src"))
    if obj is None or [x.lower() for x in obj] != ["'none'"]:
        out.append(issue(C, "object-src is not 'none'", "medium",
                         "Plugins (<object>/<embed>) can be used to execute script; set object-src 'none'."))
    if "base-uri" not in d:
        out.append(issue(C, "base-uri not set", "low",
                         "An injected <base> tag can redirect relative script URLs, even under nonce-based CSP."))
    if "frame-ancestors" not in d:
        out.append(issue(C, "frame-ancestors not set in CSP", "info", "Clickjacking protection relies on X-Frame-Options."))
    if not out:
        out.append(issue(C, "CSP looks strong", "info", evidence=value[:500]))
    return out


# ------------------------------------------------------------------ headers / cookies / TLS
def check_headers(resp: dict, https: bool) -> list[dict]:
    h = resp["headers"]
    H = "Security headers"
    out = evaluate_csp(h.get("content-security-policy"), h.get("content-security-policy-report-only"))
    if https:
        hsts = h.get("strict-transport-security")
        if not hsts:
            out.append(issue(H, "Missing Strict-Transport-Security (HSTS)", "medium",
                             "Users can be downgraded to HTTP by an on-path attacker (SSL stripping)."))
        else:
            m = re.search(r"max-age=(\d+)", hsts)
            if not m or int(m.group(1)) < 15552000:
                out.append(issue(H, "HSTS max-age shorter than 180 days", "low", evidence=hsts))
            if "includesubdomains" not in hsts.lower():
                out.append(issue(H, "HSTS without includeSubDomains", "info", evidence=hsts))
    else:
        out.append(issue(H, "Page served over plain HTTP", "high", "All traffic, including cookies, is readable and modifiable in transit."))
    csp = h.get("content-security-policy", "")
    if not h.get("x-frame-options") and "frame-ancestors" not in csp:
        out.append(issue(H, "No clickjacking protection", "medium",
                         "Neither X-Frame-Options nor CSP frame-ancestors is set, so the page can be framed."))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(issue(H, "Missing X-Content-Type-Options: nosniff", "low", "Browsers may MIME-sniff responses into script."))
    if not h.get("referrer-policy"):
        out.append(issue(H, "Missing Referrer-Policy", "info", "Full URLs (possibly with tokens) may leak to third parties via Referer."))
    if not h.get("permissions-policy"):
        out.append(issue(H, "Missing Permissions-Policy", "info"))
    for name in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"):
        v = h.get(name)
        if v and re.search(r"\d", v):
            out.append(issue("Information disclosure", f"Version disclosed in {name.title()} header", "low",
                             "Exact versions help attackers pick known exploits.", f"{name}: {v}"))
    acao, acac = h.get("access-control-allow-origin"), h.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        out.append(issue("CORS", "CORS wildcard with credentials", "medium", evidence=f"ACAO: {acao}; ACAC: {acac}"))
    elif acao == "*":
        out.append(issue("CORS", "CORS allows any origin (*)", "info", "Fine for public data; check no private data is served.", f"ACAO: *"))
    return out


SESSIONY = re.compile(r"sess|sid|auth|token|jwt|login|remember|csrf|xsrf", re.I)


def check_cookies(set_cookies: list[str], https: bool) -> list[dict]:
    out = []
    for raw in set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in raw.split(";")[1:]]
        flags = {a.split("=", 1)[0]: (a.split("=", 1)[1] if "=" in a else True) for a in attrs}
        sensitive = bool(SESSIONY.search(name))
        problems = []
        if https and "secure" not in flags:
            problems.append(("missing Secure", "medium" if sensitive else "low"))
        if "httponly" not in flags:
            problems.append(("missing HttpOnly", "medium" if sensitive else "info"))
        ss = flags.get("samesite")
        if not ss:
            problems.append(("no SameSite", "low" if sensitive else "info"))
        elif str(ss).lower() == "none" and "secure" not in flags:
            problems.append(("SameSite=None without Secure", "medium"))
        for what, sev in problems:
            out.append(issue("Cookies", f"Cookie '{name}': {what}", sev,
                             "Session-like name." if sensitive else "", raw.split(";")[0][:40] + "…; " + "; ".join(attrs)))
    if set_cookies and not out:
        out.append(issue("Cookies", f"{len(set_cookies)} cookie(s) set with good flags", "info"))
    return out


def check_tls(tls: dict) -> list[dict]:
    T = "TLS"
    if tls.get("valid") is False:
        return [issue(T, "Invalid TLS certificate", "high", tls.get("error", ""))]
    if tls.get("valid") is None:
        return [issue(T, "TLS check failed", "info", tls.get("error", ""))]
    out = []
    days = tls.get("days_left")
    if days is not None and days < 0:
        out.append(issue(T, "Certificate expired", "high", f"Expired {-days} days ago"))
    elif days is not None and days < 21:
        out.append(issue(T, f"Certificate expires in {days} days", "low"))
    if tls.get("version") in ("TLSv1", "TLSv1.1", "SSLv3"):
        out.append(issue(T, f"Outdated protocol {tls['version']}", "medium"))
    out.append(issue(T, f"{tls.get('version')} · {tls.get('cipher')}", "info",
                     f"Subject: {tls.get('subject')}\nIssuer: {tls.get('issuer')}\nExpires: {tls.get('not_after')} "
                     f"({days} days)\nSANs: {', '.join(tls.get('san', [])[:20])}"))
    return out


# ------------------------------------------------------------------ page content
INTERESTING_COMMENT = re.compile(r"todo|fixme|hack|password|passwd|secret|api[_-]?key|token|debug|admin|internal|staging|dev\b", re.I)


def check_page(page: dict) -> list[dict]:
    out = []
    P = "Page"
    for m in page.get("mixed", [])[:30]:
        active = m["tag"] in ("script", "iframe", "link", "embed", "object")
        out.append(issue(P, f"Mixed content: <{m['tag']}> over HTTP", "high" if active else "low",
                         "Active mixed content lets a network attacker inject script." if active else "", m["url"]))
    https = page.get("https")
    for f in page.get("forms", []):
        action = f.get("action") or ""
        if f.get("password") and (not https or action.startswith("http:")):
            out.append(issue(P, "Password form submits over HTTP", "high", evidence=action))
        elif https and action.startswith("http:"):
            out.append(issue(P, "Form submits to an HTTP URL", "medium", evidence=action))
        if f.get("method") == "post" and not f.get("csrf"):
            out.append(issue(P, "POST form without a visible CSRF token", "low",
                             "Verify manually: the app may rely on SameSite cookies or a header-based token.", action))
    for c in page.get("comments", []):
        if INTERESTING_COMMENT.search(c):
            out.append(issue("Information disclosure", "Interesting HTML comment", "info", evidence=c))
    tokens = [k for k in page.get("localStorage", []) + page.get("sessionStorage", []) if SESSIONY.search(k)]
    if tokens:
        out.append(issue(P, "Auth-like values in Web Storage", "low",
                         "Tokens in localStorage/sessionStorage are readable by any XSS, unlike HttpOnly cookies.",
                         ", ".join(tokens)))
    js_sess = [c for c in page.get("jsCookies", []) if SESSIONY.search(c)]
    if js_sess:
        out.append(issue("Cookies", "Session-like cookies readable from JavaScript", "medium",
                         "These cookies lack HttpOnly, so an XSS can steal them.", ", ".join(js_sess)))
    return out


# ------------------------------------------------------------------ technologies
NPM_NAMES = {"jquery": "jquery", "react": "react", "angularjs": "angular", "angular": "@angular/core", "vue": "vue",
             "lodash": "lodash", "moment": "moment", "bootstrap": "bootstrap", "dompurify": "dompurify",
             "handlebars": "handlebars", "jquery-ui": "jquery-ui", "underscore": "underscore"}
SRC_VERSION = re.compile(r"/(jquery|jquery-ui|bootstrap|angular(?:js)?|vue|react|lodash|moment|underscore|handlebars|dompurify)"
                         r"(?:[.\-@/]|\.min)?(?:js/)?[\-@/]?v?(\d+\.\d+(?:\.\d+)?)", re.I)


def detect_tech(page: dict, headers: dict) -> list[dict]:
    found: dict[str, str] = {}
    for k, v in (page.get("globals") or {}).items():
        found[k] = v or found.get(k, "")
    for src in page.get("scripts", []):
        m = SRC_VERSION.search(src)
        if m:
            name = m.group(1).lower().replace("angularjs", "angularjs")
            name = "angularjs" if name == "angular" else name
            found.setdefault(name, m.group(2))
            if not found[name]:
                found[name] = m.group(2)
    gen = page.get("generator")
    if gen:
        found[gen.split()[0].lower()] = (re.search(r"\d+(\.\d+)+", gen) or [""])[0]
    for hname in ("server", "x-powered-by"):
        for token in (headers.get(hname) or "").split():
            m = re.match(r"([A-Za-z][\w\-.]*)/(\d+(?:\.\d+)*)", token)
            if m:
                found.setdefault(m.group(1).lower(), m.group(2))
            elif token and re.match(r"^[A-Za-z][\w\-]+$", token):
                found.setdefault(token.lower(), "")
    out = []
    for name, ver in sorted(found.items()):
        out.append(issue("Technologies", f"{name} {ver}".strip(), "info",
                         "Select and press 'Look up CVEs' to check known vulnerabilities." if ver else "Version unknown.",
                         tech={"name": name, "version": ver, "npm": NPM_NAMES.get(name)}))
    return out


# ------------------------------------------------------------------ JavaScript endpoints + secrets
SECRET_PATTERNS = [
    ("AWS access key id", r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "high"),
    ("Google API key", r"\bAIza[0-9A-Za-z\-_]{35}\b", "medium"),
    ("GitHub token", r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b", "high"),
    ("Slack token", r"\bxox[baprs]-[0-9A-Za-z\-]{10,}\b", "high"),
    ("Stripe live secret key", r"\bsk_live_[0-9a-zA-Z]{20,}\b", "critical"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b", "medium"),
    ("Generic secret assignment", r"(?i)\b(?:api[_-]?key|secret|passwd|password|access[_-]?token)\b\s*[:=]\s*['\"][^'\"\s]{8,}['\"]", "low"),
]
ENDPOINT_RE = re.compile(r"""["'`]((?:https?:)?//[^"'`\s<>]{4,300}|/[A-Za-z0-9_\-./{}:?=&%~]{2,200})["'`]""")
STATIC_EXT = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|webm|mp3|map)(\?|$)", re.I)
INTERESTING_EP = re.compile(r"api|graphql|v\d+/|admin|auth|login|token|internal|debug|upload|user|account|config|\.json", re.I)


def mask(s: str) -> str:
    return s if len(s) <= 12 else s[:6] + "…" + s[-4:]


def scan_js(page: dict, in_scope, proxies=None, verify=True, max_files=25) -> list[dict]:
    """Scan inline scripts + same-scope external scripts the page already loads."""
    base = page.get("url", "")
    sources = [("inline #%d" % i, t) for i, t in enumerate(page.get("inline", []))]
    fetched = 0
    for src in page.get("scripts", []):
        host = urlparse(src).hostname or ""
        if fetched >= max_files or (in_scope is not None and not in_scope(host)):
            continue
        try:
            r = requests.get(src, headers={"User-Agent": UA}, timeout=TIMEOUT, proxies=proxies, verify=verify)
            if r.ok and len(r.content) < 6_000_000:
                sources.append((src, r.text))
                fetched += 1
        except requests.RequestException:
            continue
    endpoints: dict[str, str] = {}
    secrets = []
    seen = set()
    for where, text in sources:
        for m in ENDPOINT_RE.finditer(text):
            ep = m.group(1)
            if STATIC_EXT.search(ep) or ep.startswith("//www.w3.org") or len(ep) < 3 or ep.count("/") > 15:
                continue
            endpoints.setdefault(ep, where)
        for label, pat, sev in SECRET_PATTERNS:
            for m in re.finditer(pat, text):
                val = m.group(0)
                if (label, val) in seen:
                    continue
                seen.add((label, val))
                ctx = text[max(0, m.start() - 60): m.end() + 40].replace("\n", " ")
                secrets.append(issue("JavaScript: possible secrets", f"{label}: {mask(val)}", sev,
                                     f"Found in {where}. Verify whether it is a real credential and if it is meant to be public "
                                     "(e.g. restricted browser keys) before reporting.",
                                     ctx.replace(val, mask(val))))
    eps = sorted(endpoints.items(), key=lambda kv: (not INTERESTING_EP.search(kv[0]), kv[0]))
    out = secrets
    for ep, where in eps[:300]:
        full = urljoin(base, ep) if ep.startswith("/") and not ep.startswith("//") else ep
        out.append(issue("JavaScript: endpoints", ep, "info", f"Referenced in {where}", full, url=full,
                         interesting=bool(INTERESTING_EP.search(ep))))
    out.append(issue("JavaScript: endpoints", f"Scanned {len(sources)} script(s), {len(eps)} endpoint(s)", "info"))
    return out


# ------------------------------------------------------------------ orchestration
def analyze(url: str, page: dict, in_scope=None, proxies=None, verify=True) -> dict:
    """Run every passive check. Returns {'issues': [...], 'grade': 'A'..'F', 'errors': [...]}."""
    p = urlparse(url)
    https = p.scheme == "https"
    errors, issues = [], []
    resp = {"headers": {}, "set_cookies": []}
    try:
        resp = fetch_response(url, proxies, verify)
        issues += check_headers(resp, https)
        issues += check_cookies(resp["set_cookies"], https)
    except Exception as e:  # noqa: BLE001
        errors.append(f"Response fetch failed: {e}")
    via_socks = bool(proxies) and "socks" in str(proxies)
    if https and p.hostname and not via_socks:  # raw TLS socket would bypass Tor: skip in Tor windows
        issues += check_tls(fetch_tls(p.hostname, p.port or 443))
    issues += check_page(page)
    issues += detect_tech(page, resp["headers"])
    try:
        issues += scan_js(page, in_scope, proxies, verify)
    except Exception as e:  # noqa: BLE001
        errors.append(f"JS scan failed: {e}")
    issues.sort(key=lambda i: SEV_ORDER.get(i["severity"], 9))
    return {"issues": issues, "grade": grade(issues), "errors": errors, "status": resp.get("status"),
            "headers": resp.get("headers", {})}


def grade(issues: list[dict]) -> str:
    weights = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}
    score = 100 - sum(weights.get(i["severity"], 0) for i in issues)
    for g, cut in (("A", 90), ("B", 75), ("C", 60), ("D", 40), ("E", 20)):
        if score >= cut:
            return g
    return "F"
