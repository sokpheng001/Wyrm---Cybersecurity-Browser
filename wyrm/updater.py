"""In-app updates via GitHub Releases — check, download, and install without a manual reinstall.

The update check queries the project's official GitHub release feed, compares the published version to
the running one, and (on Windows) downloads the signed-style Inno Setup installer and runs it silently.
The installer closes the running app, updates the files in place, and relaunches it — so the user only
clicks "Update". Downloads are accepted only from github.com / its release CDN, over HTTPS.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import requests

REPO = "sokpheng001/cybersecurity-browser"
API = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases/latest"
UA = "Wyrm-Updater"
_ALLOWED_HOSTS = ("github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
                  "codeload.github.com")


def _ver_tuple(v: str) -> tuple:
    nums = re.findall(r"\d+", (v or "").lstrip("vV"))
    nums = [int(x) for x in nums[:3]]
    return tuple(nums + [0] * (3 - len(nums)))


def is_newer(latest: str, current: str) -> bool:
    return _ver_tuple(latest) > _ver_tuple(current)


def _asset_for_platform(assets: list[dict]) -> dict | None:
    if sys.platform == "win32":
        pats = [r"setup.*\.exe$", r"\.exe$"]
    elif sys.platform == "darwin":
        pats = [r"\.dmg$", r"\.pkg$"]
    else:
        pats = [r"\.appimage$", r"\.deb$", r"\.tar\.gz$"]
    for pat in pats:
        for a in assets:
            if re.search(pat, a.get("name", ""), re.I):
                return a
    return None


def check(current: str, proxies=None, verify=True) -> dict:
    """Return info about the latest release and whether it is newer than `current`."""
    r = requests.get(API, headers={"User-Agent": UA, "Accept": "application/vnd.github+json"},
                     timeout=20, proxies=proxies, verify=verify)
    r.raise_for_status()
    d = r.json()
    tag = d.get("tag_name") or d.get("name") or ""
    asset = _asset_for_platform(d.get("assets") or [])
    url = asset.get("browser_download_url") if asset else None
    from urllib.parse import urlparse
    if url and urlparse(url).hostname not in _ALLOWED_HOSTS:
        url, asset = None, None  # refuse anything not hosted by GitHub
    return {
        "version": tag.lstrip("vV"),
        "tag": tag,
        "newer": bool(tag) and is_newer(tag, current),
        "notes": d.get("body") or "",
        "html_url": d.get("html_url") or RELEASES_PAGE,
        "asset_name": asset.get("name") if asset else None,
        "asset_url": url,
        "asset_size": asset.get("size", 0) if asset else 0,
    }


def download(url: str, dest: Path, proxies=None, verify=True, progress=None) -> Path:
    from urllib.parse import urlparse
    if urlparse(url).hostname not in _ALLOWED_HOSTS:
        raise ValueError("Refusing to download an update from a non-GitHub host.")
    with requests.get(url, headers={"User-Agent": UA}, timeout=120, stream=True,
                      proxies=proxies, verify=verify) as r:
        r.raise_for_status()
        total = int(r.headers.get("content-length", 0)) or 1
        got = 0
        with open(dest, "wb") as fh:
            for chunk in r.iter_content(256 * 1024):
                fh.write(chunk)
                got += len(chunk)
                if progress:
                    progress(int(got * 100 / total), got, total)
    return dest


def run_installer(path: Path) -> None:
    """Launch the downloaded installer so it can update the app in place; caller then quits."""
    import subprocess
    if sys.platform == "win32":
        # Inno Setup: close the running app, update, relaunch it; detached so it survives our exit.
        subprocess.Popen([str(path), "/SILENT", "/NORESTART", "/CLOSEAPPLICATIONS", "/RESTARTAPPLICATIONS"],
                         creationflags=0x08000000)  # CREATE_NO_WINDOW
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        import os
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass
        subprocess.Popen(["xdg-open", str(path)])
