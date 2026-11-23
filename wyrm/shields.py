#------------------------------------------------------------------------------
# Wyrm — wyrm/shields.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Shields: ad, tracker and malware blocking using Brave's open-source engine (adblock-rust via `adblock`).

Filter lists (public, community-maintained, refreshed daily in the background):
  ads      EasyList, uBlock Origin filters
  trackers EasyPrivacy
  malware  URLhaus malicious-URL filter (abuse.ch / malware-filter), uBlock Origin badware risks
Each category has its own engine, so every blocked request is reported with the reason.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path

import adblock
import requests

LISTS = {
    "ads": [("EasyList", "https://easylist.to/easylist/easylist.txt"),
            ("uBlock filters", "https://ublockorigin.github.io/uAssets/filters/filters.txt")],
    "trackers": [("EasyPrivacy", "https://easylist.to/easylist/easyprivacy.txt")],
    "malware": [("URLhaus malicious URLs", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-online.txt"),
                ("uBlock badware risks", "https://ublockorigin.github.io/uAssets/filters/badware.txt")],
    "phishing": [("Phishing URLs (OpenPhish + PhishTank)", "https://malware-filter.gitlab.io/malware-filter/phishing-filter.txt")],
}
UPDATE_EVERY = 24 * 3600

# QWebEngineUrlRequestInfo.ResourceType name -> adblock request type
RTYPE = {"MainFrame": "document", "SubFrame": "subdocument", "Stylesheet": "stylesheet", "Script": "script",
         "Image": "image", "FontResource": "font", "SubResource": "other", "Object": "object", "Media": "media",
         "Worker": "script", "SharedWorker": "script", "ServiceWorker": "script", "Prefetch": "other",
         "Favicon": "image", "Xhr": "xmlhttprequest", "Ping": "ping", "CspReport": "csp_report",
         "PluginResource": "object", "WebSocket": "websocket", "NavigationPreloadMainFrame": "document",
         "NavigationPreloadSubFrame": "subdocument", "Json": "xmlhttprequest"}


@dataclass
class PageStats:
    host: str = ""
    counts: dict = field(default_factory=lambda: {"ads": 0, "trackers": 0, "malware": 0, "phishing": 0,
                                                  "youtube": 0, "popups": 0, "params": 0, "upgraded": 0})
    blocked: list = field(default_factory=list)  # (category, url, rtype)

    def total(self) -> int:
        return sum(v for k, v in self.counts.items() if k not in ("params", "upgraded"))


def fetch_lists(cache: Path) -> dict[str, str]:
    """Download every list (worker thread). Returns {category: combined text}. Falls back to cache per list."""
    cache.mkdir(parents=True, exist_ok=True)
    out = {}
    for cat, items in LISTS.items():
        texts = []
        for name, url in items:
            f = cache / f"{cat}-{name.replace(' ', '_')}.txt"
            try:
                r = requests.get(url, timeout=60, headers={"User-Agent": "Wyrm/1.0 shields"})
                r.raise_for_status()
                f.write_text(r.text, encoding="utf-8")
            except requests.RequestException:
                pass
            if f.exists():
                texts.append(f.read_text(encoding="utf-8"))
        out[cat] = "\n".join(texts)
    (cache / "updated").write_text(str(time.time()))
    return out


def load_cached(cache: Path) -> dict[str, str]:
    out = {}
    for cat in LISTS:
        texts = [p.read_text(encoding="utf-8") for p in sorted(cache.glob(f"{cat}-*.txt"))]
        if texts:
            out[cat] = "\n".join(texts)
    return out


def build_engines(texts: dict[str, str]) -> dict[str, adblock.Engine]:
    engines = {}
    for cat, text in texts.items():
        fs = adblock.FilterSet()
        fs.add_filter_list(text)
        engines[cat] = adblock.Engine(filter_set=fs, optimize=True)
    return engines


def _signature(cache: Path) -> str:
    """Changes whenever a filter list (or the adblock library) changes: keys the saved engines and rule counts."""
    parts = [getattr(adblock, "__version__", "?")]
    for f in sorted(cache.glob("*.txt")):
        st = f.stat()
        parts.append(f"{f.name}:{st.st_size}:{st.st_mtime_ns}")
    return "|".join(parts)


def save_engines(cache: Path, engines: dict) -> None:
    """Save compiled engines (adblock's native Rust format): loading them takes ~0.08 s instead of rebuilding
    every engine from ~18 MB of filter text at each start (~0.5 s, all on the UI thread)."""
    try:
        for cat, eng in engines.items():
            eng.serialize_to_file(str(cache / f"engine-{cat}.dat"))
        (cache / "engine.sig").write_text(_signature(cache), encoding="utf-8")
    except Exception:  # noqa: BLE001 - a cache only; never break the browser over it
        pass


def load_saved_engines(cache: Path) -> dict | None:
    try:
        if (cache / "engine.sig").read_text(encoding="utf-8") != _signature(cache):
            return None
        out = {}
        for cat in LISTS:
            f = cache / f"engine-{cat}.dat"
            if f.exists():
                eng = adblock.Engine(filter_set=adblock.FilterSet(), optimize=True)
                eng.deserialize_from_file(str(f))
                out[cat] = eng
        return out or None
    except Exception:  # noqa: BLE001
        return None


def build_and_save(cache: Path) -> dict:
    """Worker thread: download fresh lists, compile them and save the compiled engines."""
    engines = build_engines(fetch_lists(cache))
    save_engines(cache, engines)
    return engines


class Shields:
    def __init__(self, data_dir: Path, settings):
        self.cache = data_dir / "filters"
        self.settings = settings
        self.engines: dict[str, adblock.Engine] = {}
        self.total_blocked = settings.value("shields/total", 0, type=int)
        self.disabled_sites: set[str] = set(settings.value("shields/disabled_sites", [], type=list) or [])
        self.malware_allow: set[str] = set()  # hosts the user chose to visit anyway (this session)
        bundled = Path(__file__).parent / "assets" / "filters"
        if not any(self.cache.glob("*.txt")) and bundled.exists():  # first run: start from the shipped snapshot
            self.cache.mkdir(parents=True, exist_ok=True)
            for f in bundled.glob("*.txt"):
                (self.cache / f.name).write_bytes(f.read_bytes())
        self.engines = load_saved_engines(self.cache) or {}
        if not self.engines:
            cached = load_cached(self.cache)
            if cached:
                self.engines = build_engines(cached)
                save_engines(self.cache, self.engines)
        self._counts: tuple[str, dict] | None = None

    # ---------------------------------------------------------- settings
    def enabled(self, what: str) -> bool:
        # cached: called several times for every network request, and each QSettings read is a registry lookup
        cache = self.__dict__.setdefault("_enabled_cache", {})
        if what not in cache:
            cache[what] = self.settings.value(f"shields/{what}", True, type=bool)
        return cache[what]

    def set_enabled(self, what: str, on: bool):
        self.settings.setValue(f"shields/{what}", on)
        self.__dict__.setdefault("_enabled_cache", {})[what] = bool(on)

    def site_enabled(self, host: str) -> bool:
        return host not in self.disabled_sites

    def set_site_enabled(self, host: str, on: bool):
        (self.disabled_sites.discard if on else self.disabled_sites.add)(host)
        self.settings.setValue("shields/disabled_sites", sorted(self.disabled_sites))

    def needs_update(self) -> bool:
        f = self.cache / "updated"
        try:
            return time.time() - float(f.read_text()) > UPDATE_EVERY
        except (OSError, ValueError):
            return True

    def last_updated(self) -> str:
        try:
            return time.strftime("%Y-%m-%d %H:%M", time.localtime(float((self.cache / "updated").read_text())))
        except (OSError, ValueError):
            return "never"

    def rule_counts(self) -> dict[str, int]:
        """Rules per category. Counted once per filter-list version (memory + counts.json), not on every Shields
        panel refresh: counting re-read ~18 MB of lists each time."""
        import json
        sig = _signature(self.cache)
        if self._counts and self._counts[0] == sig:
            return self._counts[1]
        f = self.cache / "counts.json"
        try:
            saved = json.loads(f.read_text(encoding="utf-8"))
            if saved.get("sig") == sig:
                self._counts = (sig, saved["counts"])
                return saved["counts"]
        except (OSError, ValueError, KeyError):
            pass
        counts = {cat: sum(1 for line in t.splitlines() if line and not line.startswith(("!", "[")))
                  for cat, t in load_cached(self.cache).items()}
        try:
            f.write_text(json.dumps({"sig": sig, "counts": counts}), encoding="utf-8")
        except OSError:
            pass
        self._counts = (sig, counts)
        return counts

    # ---------------------------------------------------------- decisions
    def check(self, url: str, source_url: str, rtype: str, source_host: str) -> str | None:
        """Return the category to block this request for, or None to allow it."""
        if not self.engines or not self.site_enabled(source_host):
            return None
        req = RTYPE.get(rtype, "other")
        order = ["malware", "phishing", "ads", "trackers"]
        for cat in order:
            if not self.enabled("malware" if cat == "phishing" else cat) or cat not in self.engines:
                continue
            if req == "document" and cat not in ("malware", "phishing"):
                continue  # never block top-level navigation for ads/trackers
            try:
                m = self.engines[cat].check_network_urls(url=url, source_url=source_url or url, request_type=req)
            except Exception:  # noqa: BLE001 - malformed URL etc.
                return None
            if m.matched and not m.exception:
                return cat
        return None

    def check_popup(self, url: str) -> str | None:
        """Pop-up/pop-under check: '$popup' rules in the ad lists, plus threat lists."""
        if not self.engines or not self.enabled("popups"):
            return None
        for cat in ("malware", "phishing", "ads", "trackers"):
            eng = self.engines.get(cat)
            if not eng:
                continue
            for rtype in ("popup", "document"):
                try:
                    m = eng.check_network_urls(url=url, source_url=url, request_type=rtype)
                except Exception:  # noqa: BLE001 - request type unsupported / bad URL
                    continue
                if m.matched and not m.exception:
                    return cat
        return None

    def count(self, n: int = 1):
        self.total_blocked += n
        if self.total_blocked % 25 == 0:
            self.settings.setValue("shields/total", self.total_blocked)

    def cosmetic_css(self, url: str) -> str:
        """Element-hiding CSS for a page (URL-specific selectors from the ads list)."""
        eng = self.engines.get("ads")
        if not eng or not self.enabled("ads"):
            return ""
        try:
            res = eng.url_cosmetic_resources(url)
        except Exception:  # noqa: BLE001
            return ""
        sel = [s for s in res.hide_selectors if s][:3000]
        return (",".join(sel) + "{display:none!important}") if sel else ""

    def generic_css(self, classes: list[str], ids: list[str], url: str) -> str:
        eng = self.engines.get("ads")
        if not eng or not self.enabled("ads"):
            return ""
        try:
            res = eng.url_cosmetic_resources(url)
            if res.generichide:
                return ""
            sel = eng.hidden_class_id_selectors(classes, ids, res.exceptions)
        except Exception:  # noqa: BLE001
            return ""
        return (",".join(sel[:3000]) + "{display:none!important}") if sel else ""
