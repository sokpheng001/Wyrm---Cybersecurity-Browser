#------------------------------------------------------------------------------
# Wyrm — wyrm/security/audit/spider.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Sopi, Kwan
#------------------------------------------------------------------------------
"""A small, polite, in-scope link/form spider that turns a site into audit targets.

crawl(seeds, fetch, in_scope, …) does a bounded breadth-first walk from the seed URLs, following same-scope
<a>/<area> links and collecting <form> submissions, and returns a de-duplicated list of request dicts
({method, url, headers, body}) for the audit engine. Only in-scope hosts are fetched; depth and page count are
capped. `fetch(url)` returns {"content_type", "text", "final_url"} or None.
"""
from __future__ import annotations

from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

_SKIP_SCHEMES = ("mailto:", "javascript:", "tel:", "data:", "#")


def _norm(u: str) -> str:
    try:
        return urlunsplit(urlsplit(u)._replace(fragment=""))
    except ValueError:
        return u


class _Extract(HTMLParser):
    def __init__(self, base: str):
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._form: dict | None = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag in ("a", "area") and a.get("href"):
            href = a["href"].strip()
            if href and not href.lower().startswith(_SKIP_SCHEMES):
                self.links.append(urljoin(self.base, href))
        elif tag == "form":
            self._form = {"action": urljoin(self.base, a.get("action") or self.base),
                          "method": (a.get("method") or "GET").upper(), "fields": []}
        elif tag in ("input", "textarea", "select") and self._form is not None:
            name = a.get("name")
            if name and a.get("type", "").lower() not in ("submit", "button", "image", "reset", "file"):
                self._form["fields"].append((name, a.get("value", "")))

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def _form_request(form: dict) -> dict:
    method = form["method"] if form["method"] in ("GET", "POST") else "GET"
    fields = form["fields"] or []
    if method == "GET":
        parts = urlsplit(form["action"])
        q = parse_qsl(parts.query, keep_blank_values=True) + fields
        return {"method": "GET", "url": urlunsplit(parts._replace(query=urlencode(q))), "headers": {}, "body": ""}
    return {"method": "POST", "url": form["action"],
            "headers": {"Content-Type": "application/x-www-form-urlencoded"}, "body": urlencode(fields)}


def crawl(seeds, fetch, in_scope, max_pages: int = 60, max_depth: int = 2, should_stop=None) -> list[dict]:
    """Breadth-first, in-scope crawl. Returns de-duplicated audit request dicts (visited pages + discovered forms)."""
    should_stop = should_stop or (lambda: False)
    visited: set = set()
    q = deque((s, 0) for s in seeds)
    reqs: list[dict] = []
    seen_keys: set = set()
    pages = 0

    def add(req):
        parts = urlsplit(req["url"])
        qnames = tuple(sorted(k for k, _ in parse_qsl(parts.query, keep_blank_values=True)))
        key = (req["method"], parts.hostname, parts.path, qnames, bool(req.get("body")))
        if key not in seen_keys:
            seen_keys.add(key)
            reqs.append(req)

    while q and pages < max_pages and not should_stop():
        url, depth = q.popleft()
        n = _norm(url)
        if n in visited:
            continue
        visited.add(n)
        host = urlsplit(url).hostname or ""
        if not in_scope(host):
            continue
        r = fetch(url)
        pages += 1
        add({"method": "GET", "url": url, "headers": {}, "body": ""})
        if not r or "html" not in str(r.get("content_type", "")).lower():
            continue
        ex = _Extract(r.get("final_url") or url)
        try:
            ex.feed(r.get("text", "") or "")
        except Exception:  # noqa: BLE001 - malformed HTML must not stop the crawl
            pass
        for form in ex.forms:
            if in_scope(urlsplit(form["action"]).hostname or ""):
                add(_form_request(form))
        if depth + 1 <= max_depth:
            for link in ex.links:
                if _norm(link) not in visited and in_scope(urlsplit(link).hostname or ""):
                    q.append((link, depth + 1))
    return reqs
