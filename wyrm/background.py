"""Daily new-tab background image, Brave-style.

A random photo is fetched once per day (not per tab) and cached on disk, so the new-tab page shows a
fresh image while making at most one network request a day. The fetch goes through the window's proxy
settings, and is skipped entirely in Tor windows. If the network is unavailable, the last cached image
(or none) is used, so the start page always renders.
"""
from __future__ import annotations

import base64
from datetime import date
from pathlib import Path

import requests

# Picsum serves a random photo at a fixed size with no API key or tracking account.
SOURCE = "https://picsum.photos/1920/1080"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Wyrm/1.0"


def _cache_file(cache_dir: Path) -> Path:
    return cache_dir / f"bg-{date.today().isoformat()}.jpg"


def fetch_daily(cache_dir: Path, proxies=None, verify=True) -> bytes | None:
    """Return today's background JPEG bytes, fetching+caching if needed. None on total failure."""
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        cache_dir = None
    today = _cache_file(cache_dir) if cache_dir else None
    if today and today.is_file():
        try:
            return today.read_bytes()
        except OSError:
            pass
    try:
        s = requests.Session()
        s.trust_env = False
        r = s.get(SOURCE, headers={"User-Agent": UA}, timeout=20, proxies=proxies, verify=verify, allow_redirects=True)
        r.raise_for_status()
        data = r.content
        if not data or len(data) > 8_000_000:
            raise ValueError("empty or oversized image")
    except Exception:  # noqa: BLE001 - cosmetic; fall back to any cached image
        if cache_dir:
            files = sorted(cache_dir.glob("bg-*.jpg"), reverse=True)
            if files:
                try:
                    return files[0].read_bytes()
                except OSError:
                    return None
        return None
    if today:
        try:
            today.write_bytes(data)
            for old in cache_dir.glob("bg-*.jpg"):  # keep only the last few days
                if old != today and old.stat().st_mtime < today.stat().st_mtime - 7 * 86400:
                    old.unlink(missing_ok=True)
        except OSError:
            pass
    return data


def data_uri(image: bytes | None) -> str | None:
    if not image:
        return None
    return "data:image/jpeg;base64," + base64.b64encode(image).decode("ascii")
