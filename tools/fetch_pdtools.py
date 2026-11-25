#------------------------------------------------------------------------------
# Wyrm — tools/fetch_pdtools.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Developer: @kwan (ProjectDiscovery tool integration)
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
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

BINROOT = Path(__file__).resolve().parent.parent / "wyrm" / "bin"
DEST = BINROOT / "pdtools"   # the recon/scan tool binaries
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
    fetch_tor()
    fetch_nuclei_templates()


# Invisible format characters that have slipped into upstream paths (e.g. a LEFT-TO-RIGHT MARK before "http",
# which created a second, look-alike "http" folder in the bundle). They are removed; any other non-ASCII path
# segment is rejected (skipped and reported), so every template lands under the folder its name says.
_INVISIBLE = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e"
                                    "\u2066\u2067\u2068\u2069\ufeff\u00ad"), None)


def clean_member_path(name: str):
    """Normalized relative path for a template archive member, or None to skip it (unsafe or non-ASCII)."""
    import unicodedata
    parts = []
    for seg in name.replace("\\", "/").split("/"):
        seg = unicodedata.normalize("NFC", seg).translate(_INVISIBLE).strip()
        if seg in ("", "."):
            continue
        if seg == ".." or not seg.isascii() or any(ord(c) < 32 for c in seg):
            return None
        parts.append(seg)
    return "/".join(parts) or None


def latest_templates_release(s=None) -> tuple[str, str]:
    """(tag, tarball URL) of the latest nuclei-templates RELEASE — the same set `nuclei -update-templates`
    installs, so the bundled and the auto-updated copies match (main also carries unreleased templates)."""
    s = s or requests
    r = s.get("https://api.github.com/repos/projectdiscovery/nuclei-templates/releases/latest", timeout=30,
              headers=UA)
    r.raise_for_status()
    rel = r.json()
    return rel["tag_name"], rel["tarball_url"]


def extract_templates(data: bytes, dest: Path) -> tuple[int, list[str]]:
    """Unpack a templates tarball into dest with clean paths. Returns (yaml count, skipped member names)."""
    import tarfile
    skipped, renamed = [], 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        members = tf.getmembers()
        root = members[0].name.split("/")[0] + "/" if members else ""
        for m in members:
            if not (m.name.startswith(root) and m.isfile()):
                continue   # directories are created from file paths; links/devices are never extracted
            rel = m.name[len(root):]
            clean = clean_member_path(rel)
            if clean is None:
                skipped.append(rel)
                continue
            if clean != rel:
                renamed += 1
            out = dest / clean
            out.parent.mkdir(parents=True, exist_ok=True)
            with tf.extractfile(m) as src, open(out, "wb") as fh:
                shutil.copyfileobj(src, fh)
    n = sum(1 for _ in dest.rglob("*.yaml"))
    if renamed:
        print(f"  nuclei-templates: normalized {renamed} path(s) with invisible characters")
    for name in skipped:
        print(f"  nuclei-templates: skipped non-ASCII/unsafe path {name!r}")
    return n, skipped


def fetch_nuclei_templates() -> None:
    """Bundle the latest nuclei-templates release into wyrm/bin/nuclei-templates/, so the first nuclei scan runs
    offline with no template download. Non-fatal."""
    dest = BINROOT / "nuclei-templates"
    try:
        tag, url = latest_templates_release()
        data = requests.get(url, timeout=600, headers=UA).content
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True)
        n, _ = extract_templates(data, dest)
        (dest / ".wyrm-templates.json").write_text(f'{{"tag": "{tag}", "count": {n}}}')
        print(f"  nuclei-templates {tag}: {n} templates bundled ({len(data) // 1048576} MB download)")
    except Exception as e:  # noqa: BLE001 - non-fatal
        print("  nuclei-templates skipped:", type(e).__name__, e)


def fetch_tor() -> None:
    """Download + verify the Tor Expert Bundle and unpack it into wyrm/bin/tor/, so Tor windows work right after
    install with no runtime download. Non-fatal: if it fails, Wyrm downloads Tor on first use instead."""
    import hashlib as _h
    import tarfile
    import platform as _plat
    dest = BINROOT / "tor"
    try:
        m = _plat.machine().lower()
        arch = "aarch64" if m in ("arm64", "aarch64") else "x86_64"
        osname = {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}[_plat.system()]
        tag = f"{osname}-{arch}"
        ver = requests.get("https://aus1.torproject.org/torbrowser/update_3/release/downloads.json",
                           timeout=30).json()["version"]
        base = f"https://dist.torproject.org/torbrowser/{ver}"
        name = f"tor-expert-bundle-{tag}-{ver}.tar.gz"
        sums = requests.get(f"{base}/sha256sums-signed-build.txt", timeout=30).text
        expected = next((ln.split()[0] for ln in sums.splitlines() if ln.endswith(name)), None)
        data = requests.get(f"{base}/{name}", timeout=300).content
        if not expected or _h.sha256(data).hexdigest() != expected:
            raise RuntimeError("Tor checksum mismatch")
        shutil.rmtree(dest, ignore_errors=True)
        dest.mkdir(parents=True)
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            tf.extractall(dest, filter="data")
        print(f"  tor {ver}: bundled ({len(data) // 1048576} MB)")
    except Exception as e:  # noqa: BLE001 - non-fatal
        print("  tor bundle skipped:", type(e).__name__, e)


if __name__ == "__main__":
    sys.exit(main())
