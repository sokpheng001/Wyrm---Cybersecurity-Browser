#------------------------------------------------------------------------------
# Wyrm — wyrm/updater.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
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

REPO = "sokpheng001/Wyrm---Cybersecurity-Browser"
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
        pats = [r"\.appimage$", r"\.deb$", r"linux.*\.tar\.(gz|xz)$", r"\.tar\.(gz|xz)$"]
    for pat in pats:
        for a in assets:
            if re.search(pat, a.get("name", ""), re.I):
                return a
    return None


def check(current: str, proxies=None, verify=True, build: int = 0) -> dict:
    """Latest release info and whether it is newer than the running copy: a higher version, or the same version
    with a higher build number (CI publishes every good build as the same version with a new build)."""
    r = requests.get(API, headers={"User-Agent": UA, "Accept": "application/vnd.github+json"},
                     timeout=20, proxies=proxies, verify=verify)
    r.raise_for_status()
    d = r.json()
    tag = d.get("tag_name") or d.get("name") or ""
    m = re.search(r"wyrm-build:\s*(\d+)", d.get("body") or "")  # hidden marker CI writes into the notes
    rel_build = int(m.group(1)) if m else 0
    if d.get("draft") or d.get("prerelease"):
        d = {}  # not published yet: never offer it
    # only installers that finished uploading ("starter" = upload still in progress)
    assets = [a for a in d.get("assets") or [] if a.get("state", "uploaded") == "uploaded"]
    asset = _asset_for_platform(assets)
    url = asset.get("browser_download_url") if asset else None
    from urllib.parse import urlparse
    if url and urlparse(url).hostname not in _ALLOWED_HOSTS:
        url, asset = None, None  # refuse anything not hosted by GitHub
    return {
        "version": tag.lstrip("vV"),
        "tag": tag,
        "build": rel_build,
        # newer AND its installer for this OS is ready to download: otherwise no Update button yet
        "newer": bool(tag) and bool(url) and (is_newer(tag, current)
                                              or (_ver_tuple(tag) == _ver_tuple(current)
                                                  and rel_build > int(build or 0))),
        "notes": d.get("body") or "",
        "html_url": d.get("html_url") or RELEASES_PAGE,
        "asset_name": asset.get("name") if asset else None,
        "asset_url": url,
        "asset_size": asset.get("size", 0) if asset else 0,
        "asset_sha256": _expected_sha256(asset, d.get("body") or "") if asset else None,
    }


def whats_new(notes: str, limit: int = 12) -> list[str]:
    """Plain 'what's new' lines from release notes: bullet lines only, links and markdown removed (the app
    never shows repository links)."""
    out = []
    for line in (notes or "").splitlines():
        line = line.strip()
        if not line.startswith(("- ", "* ")):
            continue
        line = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", line[2:])   # [text](url) -> text
        line = re.sub(r"https?://\S+", "", line)                       # bare links
        line = re.sub(r"\s+by @\S+.*$|\s+in\s*$", "", line)           # GitHub's "by @x in <url>" tails
        line = re.sub(r"[*_`]", "", line).strip(" -–—:")
        if line:
            out.append(line)
        if len(out) >= limit:
            break
    return out


def _expected_sha256(asset: dict, notes: str) -> str | None:
    """SHA-256 the release says this installer has: GitHub's own asset digest, else the checksum list CI writes
    into the release notes. None for old releases that have neither."""
    dg = (asset.get("digest") or "").lower()
    if dg.startswith("sha256:") and re.fullmatch(r"[0-9a-f]{64}", dg[7:]):
        return dg[7:]
    name = asset.get("name", "")
    for m in re.finditer(r"^([0-9a-fA-F]{64})\s+\*?(\S+)\s*$", notes, re.M):
        if m.group(2) == name:
            return m.group(1).lower()
    return None


def verify_sha256(path: Path, expected: str | None) -> None:
    """Raise (and delete the file) if a downloaded update doesn't match the release's checksum."""
    if not expected:
        return
    import hashlib
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    if h.hexdigest() != expected:
        try:
            path.unlink()
        except OSError:
            pass
        raise ValueError("The downloaded update is damaged or was altered (checksum mismatch); it was not installed.")


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


def run_installer(path: Path, relaunch: bool = True) -> None:
    """Launch the downloaded installer so it updates the app in place once we quit; caller then quits.
    relaunch=True ("Restart now") starts the new version afterwards; False ("Later" → installed on close) doesn't."""
    import subprocess
    if sys.platform == "win32":
        # Inno Setup, very silent: no wizard or progress window, no message boxes. Closes the app if still
        # running, updates, and (with /RELAUNCH) starts it again, so the user just sees the browser come back.
        args = [str(path), "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS"] \
            + (["/RELAUNCH"] if relaunch else [])
        subprocess.Popen(args, creationflags=0x08000000)  # CREATE_NO_WINDOW; detached so it survives our exit
    elif sys.platform == "darwin":
        if not install_macos(path, relaunch):
            subprocess.Popen(["open", str(path)])  # dev run / unexpected layout: let the user drag it
    else:
        if not install_linux(path, relaunch):
            subprocess.Popen(["xdg-open", str(path)])  # not a packaged build / unexpected archive: let the user do it


def install_linux(archive: Path, relaunch: bool = True) -> bool:
    """In-place Linux update: unpack the downloaded Wyrm-linux archive, then a detached helper waits for Wyrm to
    quit, runs the bundled install.sh (installs to ~/.local/opt/wyrm, menu entry, icon) and relaunches.
    Returns False when not running as a packaged build or the archive has no install.sh."""
    import os
    import shlex
    import subprocess
    import tarfile
    import tempfile
    if not getattr(sys, "frozen", False):
        return False
    work = Path(tempfile.mkdtemp(prefix="wyrm-update-"))
    try:
        with tarfile.open(archive) as tf:  # .tar.gz or .tar.xz
            try:
                tf.extractall(work, filter="data")  # no absolute paths / .. / device files
            except TypeError:                       # Python without extraction filters
                for m in tf.getmembers():
                    if m.name.startswith(("/", "..")) or ".." in Path(m.name).parts or not (m.isfile() or m.isdir()
                                                                                          or m.issym()):
                        raise ValueError(f"unsafe path in update archive: {m.name}")
                tf.extractall(work)
    except (OSError, tarfile.TarError, ValueError):
        return False
    inst = next(work.glob("*/install.sh"), None)
    if inst is None:
        return False
    q = shlex.quote
    script = f"""#!/bin/sh
# Wyrm Browser updater helper (generated). Waits for the app to quit, installs the new version, relaunches.
PID={os.getpid()}
i=0
while kill -0 "$PID" 2>/dev/null && [ $i -lt 120 ]; do sleep 0.5; i=$((i+1)); done
bash {q(str(inst))} >/dev/null 2>&1 || {{ xdg-open {q(str(archive))}; exit 1; }}
rm -rf {q(str(work))} {q(str(archive))}
{'nohup "$HOME/.local/opt/wyrm/Wyrm" >/dev/null 2>&1 &' if relaunch else '# installed on quit: not relaunched'}
"""
    fd, helper = tempfile.mkstemp(prefix="wyrm-update-", suffix=".sh")
    with os.fdopen(fd, "w") as fh:
        fh.write(script)
    os.chmod(helper, 0o700)
    subprocess.Popen(["/bin/sh", helper], start_new_session=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True


MAC_APP_NAME = "Wyrm Browser.app"


def _running_bundle() -> Path | None:
    """…/Wyrm Browser.app when running as a packaged macOS app (None when run from source)."""
    if not getattr(sys, "frozen", False):
        return None
    exe = Path(sys.executable).resolve()  # …/X.app/Contents/MacOS/Wyrm
    bundle = exe.parents[2]
    return bundle if bundle.suffix == ".app" else None


def install_macos(dmg: Path, relaunch: bool = True) -> bool:
    """In-place macOS update. Starts a small detached helper that waits for Wyrm to quit, copies the new app
    out of the downloaded .dmg over the installed one (same folder, e.g. /Applications), clears the download
    quarantine flag, and relaunches. Falls back to opening the .dmg if anything goes wrong. Returns False when
    not running as a packaged app (caller then just opens the .dmg)."""
    import os
    import shlex
    import subprocess
    import tempfile
    old = _running_bundle()
    if old is None:
        return False
    dest = old.parent / MAC_APP_NAME          # older installs were named Wyrm.app: replaced by the new name
    q = shlex.quote
    script = f"""#!/bin/sh
# Wyrm Browser updater helper (generated). Waits for the app to quit, swaps in the new version, relaunches.
PID={os.getpid()}
DMG={q(str(dmg))}
DEST={q(str(dest))}
OLD={q(str(old))}
i=0
while kill -0 "$PID" 2>/dev/null && [ $i -lt 120 ]; do sleep 0.5; i=$((i+1)); done
MNT=$(mktemp -d /tmp/wyrm-update.XXXXXX)
fallback() {{ hdiutil detach "$MNT" -quiet 2>/dev/null; open "$DMG"; exit 1; }}
hdiutil attach -nobrowse -readonly -noautoopen -mountpoint "$MNT" "$DMG" >/dev/null 2>&1 || fallback
SRC=$(find "$MNT" -maxdepth 1 -name "*.app" -print -quit)
[ -n "$SRC" ] || fallback
rm -rf "$DEST.updating"
ditto "$SRC" "$DEST.updating" || fallback
xattr -dr com.apple.quarantine "$DEST.updating" 2>/dev/null
rm -rf "$DEST" || fallback
[ "$OLD" != "$DEST" ] && rm -rf "$OLD"
mv "$DEST.updating" "$DEST" || fallback
hdiutil detach "$MNT" -quiet 2>/dev/null
rmdir "$MNT" 2>/dev/null
rm -f "$DMG"
{'open "$DEST"' if relaunch else '# installed on quit: not relaunched'}
"""
    fd, helper = tempfile.mkstemp(prefix="wyrm-update-", suffix=".sh")
    with os.fdopen(fd, "w") as fh:
        fh.write(script)
    os.chmod(helper, 0o700)
    subprocess.Popen(["/bin/sh", helper], start_new_session=True,
                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return True

