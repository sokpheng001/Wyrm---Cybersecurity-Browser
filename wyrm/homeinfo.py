#------------------------------------------------------------------------------
# Wyrm — wyrm/homeinfo.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
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


def fetch(proxies=None, verify=True) -> dict | None:
    """{city, region, country, lat, lon, temp_c, code, emoji, desc} or None if it can't be fetched."""
    import requests
    try:
        r = requests.get("https://ipapi.co/json/", headers=UA, timeout=12, proxies=proxies, verify=verify)
        r.raise_for_status()
        loc = r.json()
        lat, lon = loc.get("latitude"), loc.get("longitude")
        if lat is None or lon is None:
            return None
        info = {"city": loc.get("city") or "", "region": loc.get("region") or "",
                "country": loc.get("country_name") or loc.get("country") or "", "lat": lat, "lon": lon,
                "temp_c": None, "code": None, "is_day": True, "emoji": "", "desc": ""}
    except (requests.RequestException, ValueError):
        return None
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
