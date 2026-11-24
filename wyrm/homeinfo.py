#------------------------------------------------------------------------------
# Wyrm — wyrm/homeinfo.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Location + weather for the start page (date and time are a live clock drawn in the page itself).

Location comes from the IP address (no GPS, no key), weather from Open-Meteo (no key). Both are fetched through
the browser's own network settings, so a proxy / Tor route them too — meaning the "location" reflects the exit
IP you are browsing from, which is what a tester usually wants to confirm. Off by default in private / Tor
windows; the user can turn it off entirely in Settings.
"""
from __future__ import annotations

# WMO weather codes (Open-Meteo) -> (emoji, text)
_WMO = {
    0: ("☀️", "Clear"), 1: ("🌤️", "Mainly clear"), 2: ("⛅", "Partly cloudy"), 3: ("☁️", "Overcast"),
    45: ("🌫️", "Fog"), 48: ("🌫️", "Rime fog"),
    51: ("🌦️", "Light drizzle"), 53: ("🌦️", "Drizzle"), 55: ("🌧️", "Heavy drizzle"),
    56: ("🌧️", "Freezing drizzle"), 57: ("🌧️", "Freezing drizzle"),
    61: ("🌦️", "Light rain"), 63: ("🌧️", "Rain"), 65: ("🌧️", "Heavy rain"),
    66: ("🌧️", "Freezing rain"), 67: ("🌧️", "Freezing rain"),
    71: ("🌨️", "Light snow"), 73: ("🌨️", "Snow"), 75: ("❄️", "Heavy snow"), 77: ("❄️", "Snow grains"),
    80: ("🌦️", "Showers"), 81: ("🌧️", "Showers"), 82: ("⛈️", "Violent showers"),
    85: ("🌨️", "Snow showers"), 86: ("❄️", "Snow showers"),
    95: ("⛈️", "Thunderstorm"), 96: ("⛈️", "Thunderstorm, hail"), 99: ("⛈️", "Thunderstorm, hail"),
}

UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Wyrm/1.0 (start page)"}


def _geolocate(proxies, verify) -> dict | None:
    """IP geolocation from several free, keyless providers (first that answers wins) — ipapi.co is heavily
    rate-limited, so fall back to ipwho.is and ip-api.com."""
    import requests
    providers = [
        ("https://ipapi.co/json/", lambda d: (d.get("city"), d.get("region"),
                                              d.get("country_name") or d.get("country"), d.get("latitude"), d.get("longitude"))),
        ("https://ipwho.is/", lambda d: (d.get("city"), d.get("region"), d.get("country"),
                                         d.get("latitude"), d.get("longitude")) if d.get("success", True) else (None,) * 5),
        ("http://ip-api.com/json/", lambda d: (d.get("city"), d.get("regionName"), d.get("country"),
                                               d.get("lat"), d.get("lon"))),
    ]
    for url, parse in providers:
        try:
            r = requests.get(url, headers=UA, timeout=10, proxies=proxies, verify=verify)
            r.raise_for_status()
            city, region, country, lat, lon = parse(r.json())
            if lat is not None and lon is not None:
                return {"city": city or "", "region": region or "", "country": country or "",
                        "lat": lat, "lon": lon}
        except (requests.RequestException, ValueError, TypeError):
            continue
    return None


def geocode_all(query: str, proxies=None, verify=True, count: int = 8) -> list[dict]:
    """Up to `count` place matches for what the user typed, so they can pick the exact one (disambiguation —
    the accurate pattern other browsers use). Each: {city, region, country, lat, lon, label}."""
    import requests
    q = (query or "").strip()
    if not q:
        return []
    try:
        r = requests.get("https://geocoding-api.open-meteo.com/v1/search", headers=UA, timeout=10,
                         proxies=proxies, verify=verify,
                         params={"name": q, "count": count, "language": "en", "format": "json"})
        r.raise_for_status()
        out = []
        for g in (r.json() or {}).get("results") or []:
            if g.get("latitude") is None or g.get("longitude") is None:
                continue
            city, region, country = g.get("name") or "", g.get("admin1") or "", g.get("country") or ""
            label = ", ".join(x for x in (city, region, country) if x)
            out.append({"city": city, "region": region, "country": country,
                        "lat": g["latitude"], "lon": g["longitude"], "label": label})
        return out
    except (requests.RequestException, ValueError, TypeError):
        return []


def geocode(query: str, proxies=None, verify=True) -> dict | None:
    """Look up a place the user typed (e.g. "Busan") -> {city, region, country, lat, lon}, via Open-Meteo's
    keyless geocoding API. Used to let the user set their location manually when IP geolocation is wrong
    (IP points at the ISP/exit, not the user)."""
    import requests
    q = (query or "").strip()
    if not q:
        return None
    try:
        r = requests.get("https://geocoding-api.open-meteo.com/v1/search", headers=UA, timeout=10,
                         proxies=proxies, verify=verify,
                         params={"name": q, "count": 1, "language": "en", "format": "json"})
        r.raise_for_status()
        res = (r.json() or {}).get("results") or []
        if not res:
            return None
        g = res[0]
        if g.get("latitude") is None or g.get("longitude") is None:
            return None
        return {"city": g.get("name") or "", "region": g.get("admin1") or "",
                "country": g.get("country") or "", "lat": g["latitude"], "lon": g["longitude"]}
    except (requests.RequestException, ValueError, TypeError):
        return None


def fetch_favicon(domain: str, url: str, proxies=None, verify=True) -> bytes | None:
    """Fetch a site's favicon for the start-page shortcuts — directly from the site (privacy-respecting: it only
    contacts the sites you bookmarked, never a third-party icon service). Tries /favicon.ico, then the page's
    <link rel=icon>. Returns raw image bytes, or None."""
    import re
    from urllib.parse import urljoin
    import requests

    def ok_image(r) -> bytes | None:
        ct = r.headers.get("content-type", "")
        if r.ok and r.content and len(r.content) < 600_000 and ("image" in ct or "icon" in ct
                                                                or "octet-stream" in ct or not ct):
            return r.content
        return None
    for u in (f"https://{domain}/favicon.ico", f"https://www.{domain}/favicon.ico"):
        try:
            data = ok_image(requests.get(u, headers=UA, timeout=8, proxies=proxies, verify=verify))
            if data:
                return data
        except requests.RequestException:
            continue
    try:  # parse the homepage for a declared icon
        r = requests.get(url if "://" in url else "https://" + url, headers=UA, timeout=8,
                         proxies=proxies, verify=verify)
        m = re.search(r"<link[^>]+rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*href=[\"']([^\"']+)[\"']", r.text, re.I) \
            or re.search(r"<link[^>]+href=[\"']([^\"']+)[\"'][^>]*rel=[\"'][^\"']*icon", r.text, re.I)
        if m:
            ir = requests.get(urljoin(r.url, m.group(1)), headers=UA, timeout=8, proxies=proxies, verify=verify)
            return ok_image(ir)
    except requests.RequestException:
        pass
    return None


def reverse_geocode(lat, lon, proxies=None, verify=True) -> dict | None:
    """Coordinates (from the OS location service) -> {city, region, country, lat, lon}, via BigDataCloud's
    keyless reverse-geocoding. Used to label a precise Wi-Fi/GPS fix with a human place name."""
    import requests
    try:
        r = requests.get("https://api.bigdatacloud.net/data/reverse-geocode-client", headers=UA, timeout=10,
                         proxies=proxies, verify=verify,
                         params={"latitude": lat, "longitude": lon, "localityLanguage": "en"})
        r.raise_for_status()
        d = r.json() or {}
        city = d.get("city") or d.get("locality") or d.get("principalSubdivision") or ""
        return {"city": city, "region": d.get("principalSubdivision") or "",
                "country": d.get("countryName") or "", "lat": lat, "lon": lon}
    except (requests.RequestException, ValueError, TypeError):
        return {"city": "", "region": "", "country": "", "lat": lat, "lon": lon}


def fetch(proxies=None, verify=True, place: dict | None = None) -> dict | None:
    """{city, region, country, lat, lon, temp_c, code, is_day, emoji, desc} or None if it can't be fetched.

    When `place` (a {city, country, lat, lon} the user set manually) is given, use it instead of IP geolocation."""
    import requests
    if place and place.get("lat") is not None and place.get("lon") is not None:
        loc = {"city": place.get("city", ""), "region": place.get("region", ""),
               "country": place.get("country", ""), "lat": place["lat"], "lon": place["lon"]}
    else:
        loc = _geolocate(proxies, verify)
    if loc is None:
        return None
    lat, lon = loc["lat"], loc["lon"]
    info = {**loc, "temp_c": None, "code": None, "is_day": True, "emoji": "", "desc": ""}
    try:
        w = requests.get("https://api.open-meteo.com/v1/forecast", headers=UA, timeout=12,
                         proxies=proxies, verify=verify,
                         params={"latitude": lat, "longitude": lon,
                                 "current": "temperature_2m,weather_code,is_day"})
        w.raise_for_status()
        cur = (w.json() or {}).get("current") or {}
        code = int(cur.get("weather_code", -1))
        info["temp_c"] = cur.get("temperature_2m")
        info["code"] = code
        info["is_day"] = bool(cur.get("is_day", 1))
        info["emoji"], info["desc"] = _WMO.get(code, ("🌡️", ""))
    except (requests.RequestException, ValueError, TypeError):
        pass
    return info
