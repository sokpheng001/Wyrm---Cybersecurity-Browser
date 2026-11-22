#------------------------------------------------------------------------------
# Wyrm — wyrm/security/techdetect.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Wappalyzer-style technology detection of the page in a tab, done inside the browser.

Fingerprints: ProjectDiscovery's wappalyzergo data (MIT; ~7,700 technologies, the open Wappalyzer format). Unlike
a static fetch, the live page is inspected: JavaScript globals (jQuery.fn.jquery, React.version, next.version...),
DOM elements / attributes / properties, every script URL (also ones added after load), inline scripts, meta tags,
cookies, the HTML and the response headers. Most versions come from the JS globals and script URLs.

    collect_js(fp)            -> JavaScript to run in the page's main world (returns the evidence as JSON)
    analyze(fp, evidence)     -> [{name, version, categories, confidence}]
"""
from __future__ import annotations

import json
import re
import time
from functools import lru_cache
from pathlib import Path

FP_URL = "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/fingerprints_data.json"
CAT_URL = "https://raw.githubusercontent.com/projectdiscovery/wappalyzergo/main/categories_data.json"
BUNDLED = Path(__file__).resolve().parents[1] / "assets" / "tech"
REFRESH = 7 * 86400  # refresh the cached fingerprints weekly

# Technology logos (the Wappalyzer icon set, MIT, via the open enthec/webappanalyzer fork). There are ~7,000 of
# them, so instead of bundling the lot we fetch each detected technology's icon on demand and cache it locally
# (data_dir/tech-icons). A page usually uses a handful, so this is a few small files and then it's offline.
ICON_BASE_URL = "https://raw.githubusercontent.com/enthec/webappanalyzer/main/src/images/icons/"


_ICON_INDEX: "dict | None" = None


def icon_for(name: str) -> str:
    """The icon filename for a technology name (from the bundled fingerprints), e.g. 'Nginx' -> 'Nginx.svg'."""
    global _ICON_INDEX
    if _ICON_INDEX is None:
        _ICON_INDEX = {}
        f = BUNDLED / "fingerprints.json"
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            apps = d.get("apps", d)
            _ICON_INDEX = {n: a.get("icon", "") for n, a in apps.items() if a.get("icon")}
        except Exception:  # noqa: BLE001
            _ICON_INDEX = {}
    return _ICON_INDEX.get(name, "")


def ensure_icon(icon: str, cache: Path, proxies=None, verify=True) -> "Path | None":
    """Return a local path to the technology's logo, downloading + caching it on first use. None if unavailable."""
    if not icon or "/" in icon or "\\" in icon or ".." in icon:
        return None
    f = cache / icon
    if f.exists():
        return f if f.stat().st_size else None
    try:
        import requests
        from urllib.parse import quote
        r = requests.get(ICON_BASE_URL + quote(icon), timeout=20, proxies=proxies, verify=verify,
                         headers={"User-Agent": "Wyrm (tech logos)"})
        cache.mkdir(parents=True, exist_ok=True)
        if r.status_code == 200 and r.content and len(r.content) < 2_000_000:
            f.write_bytes(r.content)
            return f
        f.write_bytes(b"")  # remember the miss so we don't hammer the server every detection
    except Exception:  # noqa: BLE001 - offline / blocked: just show no logo
        return None
    return None


def _fetch(cache: Path, name: str, url: str) -> Path | None:
    f = cache / name
    try:
        fresh = f.exists() and time.time() - f.stat().st_mtime < REFRESH
        if not fresh:
            import requests
            r = requests.get(url, timeout=30, headers={"User-Agent": "Wyrm (tech fingerprints)"})
            r.raise_for_status()
            json.loads(r.text)  # must be valid before replacing the cache
            cache.mkdir(parents=True, exist_ok=True)
            f.write_text(r.text, encoding="utf-8")
    except Exception:  # noqa: BLE001 - offline: use what we have
        pass
    if f.exists():
        return f
    b = BUNDLED / name
    return b if b.exists() else None


class Fingerprints:
    """The fingerprint database, loaded once."""

    def __init__(self, apps: dict, cats: dict):
        self.apps = apps
        self.cats = {int(k): (v.get("name") if isinstance(v, dict) else str(v)) for k, v in cats.items()}
        self.js_keys = sorted({k for a in apps.values() for k in (a.get("js") or {})})
        dom = set()
        for a in apps.values():
            d = a.get("dom")
            if isinstance(d, str):
                dom.add(d)
            elif isinstance(d, list):
                dom.update(x for x in d if isinstance(x, str))
            elif isinstance(d, dict):
                dom.update(d)
        self.dom_selectors = sorted(dom)
        self.meta_names = sorted({k.lower() for a in apps.values() for k in (a.get("meta") or {})})

    @classmethod
    def load(cls, cache: Path) -> "Fingerprints":
        fp = _fetch(cache, "fingerprints.json", FP_URL)
        cat = _fetch(cache, "categories.json", CAT_URL)
        if fp is None:
            raise RuntimeError("The technology fingerprints aren't available (offline, and none cached yet).")
        apps = json.loads(fp.read_text(encoding="utf-8"))
        apps = apps.get("apps", apps)
        cats = json.loads(cat.read_text(encoding="utf-8")) if cat else {}
        return cls(apps, cats)


# ---------------------------------------------------------------- evidence collection (runs in the page)
def collect_js(fp: Fingerprints) -> str:
    """One script for the page's main world. Returns a JSON string with everything the fingerprints look at."""
    return """(function(JS_KEYS, DOM_SEL){
  var out = {js:{}, dom:{}, scriptSrc:[], scripts:[], meta:{}, cookies:document.cookie || "", url:location.href};
  function walk(path){
    var parts = path.split('.'), o = window;
    for (var i = 0; i < parts.length; i++) {
      if (o === null || o === undefined) return undefined;
      try { o = o[parts[i]]; } catch (e) { return undefined; }
    }
    return o;
  }
  JS_KEYS.forEach(function(k){
    var v = walk(k);
    if (v === undefined || v === null) return;
    var t = typeof v;
    out.js[k] = (t === 'string' || t === 'number' || t === 'boolean') ? String(v).slice(0, 200) : true;
  });
  DOM_SEL.forEach(function(sel){
    var nodes;
    try { nodes = document.querySelectorAll(sel); } catch (e) { return; }
    if (!nodes.length) return;
    var n = nodes[0], attrs = {}, props = {};
    for (var i = 0; i < n.attributes.length && i < 40; i++) attrs[n.attributes[i].name] = n.attributes[i].value.slice(0, 300);
    out.dom[sel] = {attrs: attrs, text: (n.textContent || '').slice(0, 300), node: n};
  });
  // properties are fingerprint-specific: keep the node out of JSON, look them up on demand below
  var domOut = {};
  Object.keys(out.dom).forEach(function(sel){
    var d = out.dom[sel], node = d.node, pv = {};
    for (var p in node) { if (p.charAt(0) === '_' || p.indexOf('__') >= 0) { try { var x = node[p]; pv[p] = (typeof x === 'string' || typeof x === 'number') ? String(x).slice(0,200) : true; } catch(e){} } }
    domOut[sel] = {attrs: d.attrs, text: d.text, props: pv};
  });
  out.dom = domOut;
  var ss = document.getElementsByTagName('script');
  for (var i = 0; i < ss.length; i++) {
    if (ss[i].src) out.scriptSrc.push(ss[i].src);
    else if (out.scripts.length < 60) out.scripts.push((ss[i].textContent || '').slice(0, 20000));
  }
  try { performance.getEntriesByType('resource').forEach(function(e){
    if (e.initiatorType === 'script' && out.scriptSrc.indexOf(e.name) < 0) out.scriptSrc.push(e.name); }); } catch (e) {}
  var ms = document.getElementsByTagName('meta');
  for (var i = 0; i < ms.length; i++) {
    var nm = (ms[i].getAttribute('name') || ms[i].getAttribute('property') || ms[i].getAttribute('http-equiv') || '').toLowerCase();
    if (nm) out.meta[nm] = (out.meta[nm] ? out.meta[nm] + '\\n' : '') + (ms[i].getAttribute('content') || '');
  }
  out.html = document.documentElement.outerHTML.slice(0, 1500000);
  return JSON.stringify(out);
})(%s, %s);""" % (json.dumps(fp.js_keys), json.dumps(fp.dom_selectors))


# ---------------------------------------------------------------- matching
@lru_cache(maxsize=40000)
def _compile(pattern: str):
    """Wappalyzer pattern "regex\\;version:\\1\\;confidence:50" -> (compiled regex | None, version tpl, confidence)."""
    parts = pattern.split("\\;")
    rx, ver, conf = parts[0], "", 100
    for p in parts[1:]:
        if p.startswith("version:"):
            ver = p[8:]
        elif p.startswith("confidence:"):
            try:
                conf = int(p[11:])
            except ValueError:
                pass
    if rx == "":
        return None, ver, conf
    try:
        return re.compile(rx, re.I), ver, conf
    except re.error:
        try:  # JS-only syntax: drop lookbehinds and retry
            return re.compile(re.sub(r"\(\?<[=!][^)]*\)", "", rx), re.I), ver, conf
        except re.error:
            return False, ver, conf


def _version(tpl: str, m) -> str:
    if not tpl or m is None:
        return ""
    groups = (m.group(0),) + m.groups()

    def g(i):
        return groups[i] if i < len(groups) and groups[i] else ""
    tern = re.fullmatch(r"\\(\d+)\?([^:]*):(.*)", tpl)  # "\1?yes:no"
    if tern:
        return tern.group(2) if g(int(tern.group(1))) else tern.group(3)
    v = re.sub(r"\\(\d+)", lambda x: g(int(x.group(1))), tpl).strip()
    return v if len(v) < 40 else ""


def _test(pattern, value: str):
    """(matched, version, confidence) for one pattern against one value."""
    rx, ver, conf = _compile(pattern if isinstance(pattern, str) else "")
    if rx is False:
        return False, "", 0
    if rx is None:  # "" means: present
        return True, "", conf
    m = rx.search(value)
    return (True, _version(ver, m), conf) if m else (False, "", 0)


def _as_list(x):
    return x if isinstance(x, list) else [x] if isinstance(x, str) else []


def analyze(fp: Fingerprints, ev: dict, headers: dict | None = None) -> list[dict]:
    """Match every fingerprint against the page evidence. Returns detections sorted by category then name."""
    headers = {k.lower(): str(v) for k, v in (headers or {}).items()}
    cookies = {}
    for part in (ev.get("cookies") or "").split(";"):
        if "=" in part:
            k, _, v = part.strip().partition("=")
            cookies[k.lower()] = v
    for line in (headers.get("set-cookie") or "").splitlines():
        k, _, v = line.split(";")[0].strip().partition("=")
        if k:
            cookies[k.lower()] = v
    meta = {k.lower(): v for k, v in (ev.get("meta") or {}).items()}
    js = ev.get("js") or {}
    dom = ev.get("dom") or {}
    srcs = ev.get("scriptSrc") or []
    scripts = ev.get("scripts") or []
    html = ev.get("html") or ""
    found: dict[str, dict] = {}

    def hit(name, version, conf):
        f = found.setdefault(name, {"name": name, "version": "", "confidence": 0})
        f["confidence"] = min(100, f["confidence"] + conf)
        if version and (not f["version"] or len(version) > len(f["version"])):
            f["version"] = version

    for name, a in fp.apps.items():
        for k, pat in (a.get("headers") or {}).items():
            if k.lower() in headers:
                ok, v, c = _test(pat, headers[k.lower()])
                if ok:
                    hit(name, v, c)
        for k, pat in (a.get("cookies") or {}).items():
            if k.lower() in cookies:
                ok, v, c = _test(pat, cookies[k.lower()])
                if ok:
                    hit(name, v, c)
        for k, pats in (a.get("meta") or {}).items():
            if k.lower() in meta:
                for pat in _as_list(pats) or [""]:
                    ok, v, c = _test(pat, meta[k.lower()])
                    if ok:
                        hit(name, v, c)
        for k, pat in (a.get("js") or {}).items():
            if k in js:
                val = js[k]
                ok, v, c = _test(pat, "" if val is True else str(val))
                if ok or pat == "":
                    hit(name, v, c or 100)
        for pat in _as_list(a.get("scriptSrc")):
            for s in srcs:
                ok, v, c = _test(pat, s)
                if ok:
                    hit(name, v, c)
                    break
        for pat in _as_list(a.get("scripts")):
            for s in scripts:
                ok, v, c = _test(pat, s)
                if ok:
                    hit(name, v, c)
                    break
        for pat in _as_list(a.get("html")):
            ok, v, c = _test(pat, html)
            if ok:
                hit(name, v, c)
        d = a.get("dom")
        if d:
            items = d.items() if isinstance(d, dict) else ((s, {"exists": ""}) for s in _as_list(d))
            for sel, rule in items:
                node = dom.get(sel)
                if node is None:
                    continue
                if not isinstance(rule, dict) or "exists" in rule:
                    hit(name, "", 100)
                for attr, pat in ((rule.get("attributes") or {}).items() if isinstance(rule, dict) else ()):
                    if attr in node.get("attrs", {}):
                        ok, v, c = _test(pat, node["attrs"][attr])
                        if ok:
                            hit(name, v, c)
                for prop, pat in ((rule.get("properties") or {}).items() if isinstance(rule, dict) else ()):
                    if prop in node.get("props", {}):
                        pv = node["props"][prop]
                        ok, v, c = _test(pat, "" if pv is True else str(pv))
                        if ok or pat == "":
                            hit(name, v, c or 100)
                if isinstance(rule, dict) and "text" in rule:
                    ok, v, c = _test(rule["text"], node.get("text", ""))
                    if ok:
                        hit(name, v, c)
    # implies (WordPress -> PHP, MySQL; Next.js -> React, Node.js ...), applied until nothing new appears
    changed = True
    while changed:
        changed = False
        for name in list(found):
            for imp in _as_list((fp.apps.get(name) or {}).get("implies")):
                target = imp.split("\\;")[0]
                if target in fp.apps and target not in found:
                    found[target] = {"name": target, "version": "", "confidence": 100, "implied": True}
                    changed = True
    out = []
    for f in found.values():
        a = fp.apps.get(f["name"], {})
        f["categories"] = [fp.cats.get(c, str(c)) for c in a.get("cats", [])]
        f["website"] = a.get("website", "")
        f["icon"] = a.get("icon", "")
        out.append(f)
    return sorted(out, key=lambda f: ((f["categories"] or ["~"])[0].lower(), f["name"].lower()))
