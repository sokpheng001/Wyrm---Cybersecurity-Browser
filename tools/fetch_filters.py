#------------------------------------------------------------------------------
# Wyrm — tools/fetch_filters.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Download a snapshot of the Shields filter lists into wyrm/assets/filters/ (run at build time),
so a fresh install blocks ads, trackers, malware and phishing immediately, even before the first update.

    python tools/fetch_filters.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wyrm.shields import fetch_lists  # noqa: E402

dest = Path(__file__).resolve().parent.parent / "wyrm" / "assets" / "filters"
texts = fetch_lists(dest)
print("filter snapshot:", {k: f"{len(v) // 1024} KB" for k, v in texts.items()})

# Technology fingerprints (ProjectDiscovery wappalyzergo, MIT) for Scanner -> Technologies, so detection works
# offline from the first run; the browser refreshes its own copy weekly.
import requests  # noqa: E402
from wyrm.security import techdetect  # noqa: E402

tech = Path(__file__).resolve().parent.parent / "wyrm" / "assets" / "tech"
tech.mkdir(parents=True, exist_ok=True)
for name, url in (("fingerprints.json", techdetect.FP_URL), ("categories.json", techdetect.CAT_URL)):
    r = requests.get(url, timeout=60)
    r.raise_for_status()
    import json  # noqa: E402
    json.loads(r.text)
    (tech / name).write_text(r.text, encoding="utf-8")
print("tech fingerprints:", {p.name: f"{p.stat().st_size // 1024} KB" for p in tech.glob("*.json")})

# Background videos for the start page (open-codec WebM, CC0/CC-BY, free to use). Bundled at build time and
# served locally; the "Video wallpapers" option only appears if at least one downloaded. Non-fatal: a failed
# download just means fewer (or no) built-in video wallpapers; local upload still works.
vdir = Path(__file__).resolve().parent.parent / "wyrm" / "assets" / "video"
vdir.mkdir(parents=True, exist_ok=True)
VIDEO_URLS = [
    "https://test-videos.co.uk/vids/jellyfish/webm/vp9/720/Jellyfish_720_10s_5MB.webm",
    "https://test-videos.co.uk/vids/bigbuckbunny/webm/vp9/720/Big_Buck_Bunny_720_10s_5MB.webm",
    "https://interactive-examples.mdn.mozilla.net/media/cc0-videos/flower.webm",
]
got = 0
for i, vu in enumerate(VIDEO_URLS):
    try:
        vr = requests.get(vu, timeout=90, headers={"User-Agent": "Mozilla/5.0 (Wyrm build)"})
        if vr.ok and vr.content[:4] == b"\x1aE\xdf\xa3" and len(vr.content) < 30 * 1024 * 1024:  # EBML (webm) header
            (vdir / f"wallpaper{i}.webm").write_bytes(vr.content)
            got += 1
    except Exception as e:  # noqa: BLE001 - non-fatal
        print("  video skip:", type(e).__name__, vu[:60])
print(f"background videos: {got} bundled")
