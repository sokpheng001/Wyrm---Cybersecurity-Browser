#------------------------------------------------------------------------------
# Wyrm — tools/fetch_pdtools.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Developer: @kwan (ProjectDiscovery tool integration)
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Download the ProjectDiscovery tools into wyrm/bin/ (run at build time) so they ship inside Wyrm.

Pinned versions, official GitHub release zips only, each verified against the SHA-256 in that release's
checksums file before it is unpacked. Builds for the OS/CPU this runs on (CI builds each platform natively).
The tools' MIT licence texts are kept in wyrm/bin/licenses/.

    python tools/fetch_pdtools.py
"""
import hashlib
import io
import os
import platform
import re
import shutil
import stat
import sys
import zipfile
from pathlib import Path

import requests

# tool -> pinned version. Bump here to ship newer tools (checksums are fetched from the same release).
VERSIONS = {
    "subfinder": "2.17.0", "dnsx": "1.3.1", "naabu": "2.7.0", "httpx": "1.12.0", "katana": "1.8.0",
    "nuclei": "3.11.1", "tlsx": "1.5.0", "asnmap": "1.2.0", "cdncheck": "1.4.0", "uncover": "1.2.1",
    "mapcidr": "1.1.97", "alterx": "0.1.0",
}

DEST = Path(__file__).resolve().parent.parent / "wyrm" / "bin"
UA = {"User-Agent": "Wyrm build (fetch_pdtools)"}


def platform_tag() -> str:
    os_ = {"Windows": "windows", "Darwin": "macOS", "Linux": "linux"}[platform.system()]
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else "amd64" if m in ("x86_64", "amd64") else m
    return f"{os_}_{arch}"


def fetch_tool(tool: str, ver: str, tag: str, s: requests.Session) -> None:
    rel = s.get(f"https://api.github.com/repos/projectdiscovery/{tool}/releases/tags/v{ver}", timeout=30)
    rel.raise_for_status()
    assets = {a["name"]: a["browser_download_url"] for a in rel.json()["assets"]}
    zname = f"{tool}_{ver}_{tag}.zip"
    sums = next((n for n in assets if "checksums" in n and n.endswith(".txt")), None)
    if zname not in assets or not sums:
        raise SystemExit(f"{tool} v{ver}: no {zname} or checksums file in the release")
    expected = None
    for line in s.get(assets[sums], timeout=30).text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].lstrip("*") == zname:
            expected = parts[0].lower()
    if not expected or not re.fullmatch(r"[0-9a-f]{64}", expected):
        raise SystemExit(f"{tool}: no SHA-256 for {zname} in {sums}")
    data = s.get(assets[zname], timeout=300).content
    got = hashlib.sha256(data).hexdigest()
    if got != expected:
        raise SystemExit(f"{tool}: SHA-256 mismatch for {zname} (expected {expected}, got {got})")
    exe = tool + (".exe" if tag.startswith("windows") else "")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        names = {Path(n).name: n for n in z.namelist() if not n.endswith("/")}
        if exe not in names:
            raise SystemExit(f"{tool}: {exe} not found in {zname}")
        out = DEST / exe
        out.write_bytes(z.read(names[exe]))
        out.chmod(out.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        lic = next((names[n] for n in ("LICENSE.md", "LICENSE", "LICENSE.txt") if n in names), None)
        if lic:
            (DEST / "licenses" / f"{tool}.txt").write_bytes(z.read(lic))
    print(f"  {tool} v{ver}: {out.stat().st_size // 1048576} MB, sha256 ok")


def main() -> None:
    tag = platform_tag()
    shutil.rmtree(DEST, ignore_errors=True)
    (DEST / "licenses").mkdir(parents=True)
    print(f"ProjectDiscovery tools for {tag} -> {DEST}")
    with requests.Session() as s:
        s.headers.update(UA)
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:  # CI: avoids the 60 requests/hour limit for anonymous GitHub API calls
            s.headers["Authorization"] = f"Bearer {token}"
        for tool, ver in VERSIONS.items():
            fetch_tool(tool, ver, tag, s)


if __name__ == "__main__":
    sys.exit(main())
