#------------------------------------------------------------------------------
# Wyrm — wyrm/security/pdupdate.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Developer: Kwan (ProjectDiscovery tool auto-update)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Keep the bundled ProjectDiscovery tools (and nuclei templates) current.

When Wyrm is online, this checks GitHub for newer releases of each tool and, if one is out, downloads it
(official release zip, SHA-256 verified) into a writable per-user folder that pdtools.find() prefers over the
bundled copy. Throttled to once a day. Never downgrades; failures are silent (the bundled copy keeps working).
"""
from __future__ import annotations

import hashlib
import io
import json
import platform
import re
import subprocess
import sys
import time
import zipfile
from pathlib import Path

from . import pdtools

CHECK_EVERY = 86400  # once a day
UA = {"User-Agent": "Wyrm (tool updater)"}
_NO_WINDOW = 0x08000000 if sys.platform == "win32" else 0


def _platform_tag() -> str:
    os_ = {"Windows": "windows", "Darwin": "macOS", "Linux": "linux"}.get(platform.system(), "linux")
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else "amd64" if m in ("x86_64", "amd64") else m
    return f"{os_}_{arch}"


def _ver_tuple(s: str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", s or "")
    return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)


def _installed_version(key: str) -> tuple:
    exe = pdtools.find(key)
    if not exe:
        return (0, 0, 0)
    try:
        out = subprocess.run([exe, "-version"], capture_output=True, text=True, timeout=20,
                             creationflags=_NO_WINDOW)
        return _ver_tuple((out.stdout or "") + (out.stderr or ""))
    except (OSError, subprocess.SubprocessError):
        return (0, 0, 0)


def check_and_update(user_dir: Path, proxies=None, verify=True, log=lambda *a: None) -> int:
    """Check every tool; download any that have a newer release. Returns the count updated."""
    import requests
    stamp = user_dir / ".last-check"
    try:
        if stamp.exists() and time.time() - stamp.stat().st_mtime < CHECK_EVERY:
            return 0
    except OSError:
        pass
    (user_dir / "pdtools").mkdir(parents=True, exist_ok=True)
    try:
        stamp.write_text(str(time.time()))
    except OSError:
        pass
    tag = _platform_tag()
    updated = 0
    with requests.Session() as s:
        s.headers.update(UA)
        s.proxies = proxies or {}
        s.verify = verify
        for tool in pdtools.TOOLS:
            if tool.exe:   # a preset of another tool (nuclei-full): updated with that tool
                continue
            try:
                updated += _update_one(s, tool.key, tag, user_dir, log)
            except Exception as e:  # noqa: BLE001 - one tool failing must not stop the rest
                log(f"{tool.key}: update check failed ({type(e).__name__})")
    _update_templates(user_dir, proxies, verify, log)
    return updated


def _update_one(s, key, tag, user_dir, log) -> int:
    r = s.get(f"https://api.github.com/repos/projectdiscovery/{key}/releases/latest", timeout=30)
    if not r.ok:
        return 0
    rel = r.json()
    latest = _ver_tuple(rel.get("tag_name", ""))
    if latest <= _installed_version(key):
        return 0
    ver = ".".join(map(str, latest))
    assets = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
    zname = f"{key}_{ver}_{tag}.zip"
    sums = next((n for n in assets if "checksums" in n and n.endswith(".txt")), None)
    if zname not in assets or not sums:
        return 0
    expected = None
    for line in s.get(assets[sums], timeout=30).text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == zname:
            expected = parts[0].lower()
    data = s.get(assets[zname], timeout=300).content
    if not expected or hashlib.sha256(data).hexdigest() != expected:
        log(f"{key}: checksum mismatch, skipped")
        return 0
    exe_name = key + (".exe" if sys.platform == "win32" else "")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        inner = {Path(n).name: n for n in z.namelist() if not n.endswith("/")}
        if exe_name not in inner:
            return 0
        out = user_dir / "pdtools" / exe_name
        tmp = out.with_suffix(out.suffix + ".new")
        tmp.write_bytes(z.read(inner[exe_name]))
        if sys.platform != "win32":
            tmp.chmod(0o755)
        try:
            out.unlink()
        except OSError:
            pass
        tmp.rename(out)
    log(f"{key}: updated to {ver}")
    return 1


def _update_templates(user_dir: Path, proxies, verify, log) -> None:
    """Refresh nuclei templates into the user dir (nuclei manages them itself) and log the result.

    B3: the refreshed set is the latest templates *release* — the bundle is built from the same release, so the
    two match. (An older bundle built from the main branch also had ~200 unreleased templates — exactly those
    in its .new-additions list — which is why the counts differed; nothing was being dropped.) The count is
    logged after every update, and a set that is missing, partial or much smaller than the bundled one is never
    used: pdtools.templates_dir() falls back to the bundled templates."""
    exe = pdtools.find("nuclei")
    if not exe:
        return
    tdir = user_dir / "nuclei-templates"
    before = pdtools.count_templates(tdir)
    bundled = pdtools.count_templates(pdtools.BUNDLED / "nuclei-templates")
    try:
        r = subprocess.run([exe, "-update-templates", "-update-template-dir", str(tdir), "-silent"],
                           capture_output=True, timeout=600, creationflags=_NO_WINDOW)
    except subprocess.TimeoutExpired:
        log(f"nuclei templates: update timed out; using {'previous' if before else 'bundled'} set")
        return
    except (OSError, subprocess.SubprocessError) as e:
        log(f"nuclei templates: update failed ({type(e).__name__})")
        return
    after = pdtools.count_templates(tdir)
    ok = pdtools.updated_templates_valid(tdir, bundled)
    log(f"nuclei templates: {after} after update (was {before}, bundled {bundled}, exit {r.returncode})"
        + ("" if ok else " — incomplete, using the bundled set"))
    pdtools._TPL_CACHE.clear()
