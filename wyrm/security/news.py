"""Latest cybersecurity news for the start page, from public RSS/Atom feeds (no API keys).

Fetched in parallel, merged newest-first, de-duplicated by title. Everything here is untrusted text from the
internet: titles are tag-stripped and unescaped here, then HTML-escaped again by the page renderer, and only
http(s) links are kept.
"""
from __future__ import annotations

import html
import re
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime

import requests

FEEDS = [
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("Krebs on Security", "https://krebsonsecurity.com/feed/"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("The Record", "https://therecord.media/feed"),
]
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Wyrm/1.0 (security news)"}
TIMEOUT = 12
MAX_BYTES = 3_000_000  # ignore absurdly large feeds
_TAG = re.compile(r"<[^>]+>")


def _text(s: str | None) -> str:
    return " ".join(html.unescape(_TAG.sub("", s or "")).split())


def _date(s: str | None) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        d = parsedate_to_datetime(s)  # RSS: RFC 822
    except (TypeError, ValueError):
        try:
            d = datetime.fromisoformat(s.replace("Z", "+00:00"))  # Atom: ISO 8601
        except ValueError:
            return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse(source: str, data: bytes) -> list[dict]:
    root = ET.fromstring(data)
    out = []
    for el in root.iter():
        if _local(el.tag) not in ("item", "entry"):
            continue
        f = {_local(c.tag): c for c in el}
        title = _text(f["title"].text if "title" in f else "")
        link = ""
        if "link" in f:
            link = (f["link"].text or "").strip() or f["link"].get("href", "")
        # (no `or` chaining: an Element without children is falsy)
        d_el = next((f[k] for k in ("pubDate", "published", "updated", "date") if k in f), None)
        date = _date(d_el.text if d_el is not None else None)
        if title and link.startswith(("https://", "http://")) and date:
            out.append({"title": title, "url": link, "source": source, "date": date})
    return out


def _fetch(source: str, url: str, proxies=None, verify=True) -> list[dict]:
    try:
        r = requests.get(url, headers=UA, timeout=TIMEOUT, proxies=proxies, verify=verify)
        r.raise_for_status()
        if len(r.content) > MAX_BYTES:
            return []
        return _parse(source, r.content)
    except (requests.RequestException, ET.ParseError, ValueError):
        return []


def latest(n: int = 8, proxies=None, verify=True) -> list[dict]:
    """Newest n headlines across all feeds (at most 3 per source so one site can't fill the list)."""
    with ThreadPoolExecutor(max_workers=len(FEEDS)) as ex:
        items = [i for batch in ex.map(lambda f: _fetch(*f, proxies=proxies, verify=verify), FEEDS) for i in batch]
    items.sort(key=lambda i: i["date"], reverse=True)
    seen, per_src, out = set(), {}, []
    for i in items:
        key = i["title"].lower()
        if key in seen or per_src.get(i["source"], 0) >= 3:
            continue
        seen.add(key)
        per_src[i["source"]] = per_src.get(i["source"], 0) + 1
        out.append(i)
        if len(out) >= n:
            break
    if not out:
        raise RuntimeError("no news (offline or feeds unreachable)")
    return out


def ago(d: datetime, now: datetime | None = None) -> str:
    secs = max(0, int(((now or datetime.now(timezone.utc)) - d).total_seconds()))
    if secs < 3600:
        return f"{max(1, secs // 60)}m ago"
    if secs < 86400:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"
