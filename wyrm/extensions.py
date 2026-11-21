#------------------------------------------------------------------------------
# Wyrm — wyrm/extensions.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Browser extensions (Chrome-compatible, Manifest V3): unpacking and the Chrome Web Store download.

Wyrm keeps every added extension unpacked in <data>/extensions/<folder>/ and loads that library into each
normal (non-private) profile through Qt WebEngine's QWebEngineExtensionManager (Qt 6.10+). Accepted sources:
an unpacked folder, a .zip, a .crx, or a Chrome Web Store link / extension ID. Qt only supports Manifest V3,
so older (V2) extensions are rejected here with a clear message instead of failing silently later.
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import struct
import zipfile
from pathlib import Path

LIB_DIR = "extensions"
ID_RE = re.compile(r"(?<![a-p])([a-p]{32})(?![a-p])")  # Chrome extension IDs: 32 letters a–p
# Chrome Web Store download endpoint (the same one Chrome uses); it redirects to Google's download servers
STORE_CRX = ("https://clients2.google.com/service/update2/crx?response=redirect&prodversion=138.0"
             "&acceptformat=crx2,crx3&x=id%3D{id}%26installsource%3Dondemand%26uc")
_STORE_HOSTS = ("google.com", "googleusercontent.com", "gvt1.com", "googleapis.com")
MAX_BYTES = 200 * 1024 * 1024  # refuse absurdly large packages
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/138.0 Safari/537.36 Wyrm"}


class ExtensionError(Exception):
    """A user-facing reason an extension could not be added."""


def store_id(text: str) -> str | None:
    """Extension ID from a Chrome Web Store link (chromewebstore.google.com/detail/name/<id>) or a bare ID."""
    m = ID_RE.search((text or "").strip().lower())
    return m.group(1) if m else None


def download_from_store(ext_id: str, proxies=None, verify=True) -> bytes:
    import requests
    from urllib.parse import urlparse
    r = requests.get(STORE_CRX.format(id=ext_id), headers=UA, timeout=60, proxies=proxies, verify=verify,
                     stream=True, allow_redirects=True)
    host = urlparse(r.url).hostname or ""
    if not any(host == h or host.endswith("." + h) for h in _STORE_HOSTS):
        raise ExtensionError("The Chrome Web Store redirected to an unexpected server; nothing was installed.")
    if r.status_code == 204 or r.status_code == 404:
        raise ExtensionError("The Chrome Web Store has no downloadable extension with that ID.")
    r.raise_for_status()
    data = r.raw.read(MAX_BYTES + 1, decode_content=True)
    if len(data) > MAX_BYTES:
        raise ExtensionError("That extension is too large.")
    if not data.startswith(b"Cr24"):
        raise ExtensionError("The Chrome Web Store did not return an extension package.")
    return data


def crx_to_zip(data: bytes) -> bytes:
    """Strip the CRX header (v2 or v3), leaving the zip archive inside."""
    if not data.startswith(b"Cr24") or len(data) < 16:
        raise ExtensionError("Not a valid .crx file.")
    version = struct.unpack("<I", data[4:8])[0]
    if version == 3:
        start = 12 + struct.unpack("<I", data[8:12])[0]
    elif version == 2:
        key_len, sig_len = struct.unpack("<II", data[8:16])
        start = 16 + key_len + sig_len
    else:
        raise ExtensionError(f"Unsupported .crx version {version}.")
    return data[start:]


def _safe_extract(zf: zipfile.ZipFile, dest: Path) -> None:
    root = dest.resolve()
    total = 0
    for info in zf.infolist():
        total += info.file_size
        if total > MAX_BYTES * 3:
            raise ExtensionError("That extension unpacks to an unreasonable size.")
        target = (dest / info.filename).resolve()
        if target != root and root not in target.parents:
            raise ExtensionError("The package contains unsafe file paths; nothing was installed.")
    zf.extractall(dest)


def _find_manifest_root(folder: Path) -> Path:
    if (folder / "manifest.json").is_file():
        return folder
    subs = [p for p in folder.iterdir() if p.is_dir()]
    if len(subs) == 1 and (subs[0] / "manifest.json").is_file():  # zipped with a top-level folder
        return subs[0]
    raise ExtensionError("No manifest.json found: this doesn't look like a browser extension.")


def read_manifest(folder: Path) -> dict:
    try:
        text = (folder / "manifest.json").read_text(encoding="utf-8-sig")
        return json.loads(text)
    except (OSError, ValueError) as e:
        raise ExtensionError(f"The extension's manifest.json can't be read: {e}") from e


def localized(folder: Path, manifest: dict, key: str) -> str:
    """manifest[key] with __MSG_name__ placeholders resolved from _locales/<default_locale>/messages.json."""
    val = str(manifest.get(key) or "")
    m = re.fullmatch(r"__MSG_(\w+)__", val)
    if not m:
        return val
    for loc in (manifest.get("default_locale"), "en", "en_US"):
        if not loc:
            continue
        try:
            msgs = json.loads((folder / "_locales" / loc / "messages.json").read_text(encoding="utf-8-sig"))
        except (OSError, ValueError):
            continue
        for k, v in msgs.items():
            if k.lower() == m.group(1).lower() and isinstance(v, dict) and v.get("message"):
                return str(v["message"])
    return m.group(1)


def prepare(lib: Path, source: Path | bytes, ext_id: str | None = None) -> tuple[Path, str, dict]:
    """Step 1: unpack an extension (folder path, .zip/.crx path, or raw .crx/.zip bytes) into a staging folder
    and validate it. Nothing is installed yet. Returns (staging folder, folder name, manifest)."""
    lib.mkdir(parents=True, exist_ok=True)
    tmp = lib / ".adding"
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir()
    try:
        if isinstance(source, Path) and source.is_dir():
            shutil.copytree(source, tmp / "x", ignore=shutil.ignore_patterns(".git", "node_modules"))
        else:
            data = source if isinstance(source, bytes) else Path(source).read_bytes()
            if data.startswith(b"Cr24"):
                data = crx_to_zip(data)
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    _safe_extract(zf, tmp / "x")
            except zipfile.BadZipFile as e:
                raise ExtensionError("Not a valid .zip or .crx extension package.") from e
        root = _find_manifest_root(tmp / "x")
        manifest = read_manifest(root)
        mv = manifest.get("manifest_version")
        if mv != 3:
            raise ExtensionError(f"Only Manifest V3 extensions are supported (this one is version {mv}). "
                                 "Look for a newer version of the extension.")
        name = localized(root, manifest, "name") or "extension"
        if not ext_id:
            ext_id = "x-" + hashlib.sha1(f"{name}|{manifest.get('key', '')}".encode()).hexdigest()[:12]
        return root, ext_id, manifest
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def commit(lib: Path, staged: Path, ext_id: str) -> str:
    """Step 2 (after the user agreed): move the staged extension into the library, replacing an older copy."""
    dest = lib / ext_id
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    shutil.move(str(staged), str(dest))
    discard(lib)
    return ext_id


def discard(lib: Path) -> None:
    shutil.rmtree(lib / ".adding", ignore_errors=True)


def add(lib: Path, source: Path | bytes, ext_id: str | None = None) -> tuple[str, dict]:
    """prepare() + commit() without asking (tests / trusted callers)."""
    staged, ext_id, manifest = prepare(lib, source, ext_id)
    return commit(lib, staged, ext_id), manifest


# What an extension's permissions let it do, in plain words (like Chrome's / Avast's install prompt).
_PERMS = {
    "tabs": "Read your browsing history (the address and title of every tab)",
    "history": "Read and change your browsing history",
    "cookies": "Read and change cookies, which can sign you in or out of websites",
    "webRequest": "Watch all network traffic of the pages you visit",
    "webRequestBlocking": "Block or change network requests",
    "declarativeNetRequest": "Block or redirect content on websites",
    "declarativeNetRequestWithHostAccess": "Block or redirect content on websites",
    "scripting": "Run its own code inside web pages",
    "downloads": "Manage your downloads",
    "clipboardRead": "Read what you copy to the clipboard",
    "clipboardWrite": "Change what is on the clipboard",
    "nativeMessaging": "Talk to programs installed on your computer",
    "proxy": "Control your proxy settings (where your traffic goes)",
    "privacy": "Change your privacy settings",
    "management": "Manage your other extensions",
    "debugger": "Use the debugger on pages (full control of them)",
    "geolocation": "Know your location",
    "notifications": "Show notifications",
    "bookmarks": "Read and change your bookmarks",
    "topSites": "Read your most visited sites",
    "webNavigation": "See every page you open",
    "desktopCapture": "Capture your screen",
    "tabCapture": "Capture what a tab shows and plays",
    "pageCapture": "Save complete copies of pages",
    "browsingData": "Delete your browsing data",
    "contentSettings": "Change site permissions (camera, microphone, JavaScript ...)",
}
_HIGH = {"cookies", "webRequest", "webRequestBlocking", "scripting", "nativeMessaging", "proxy", "debugger",
         "management", "desktopCapture", "clipboardRead", "privacy", "contentSettings", "history"}
_ALL_SITES = {"<all_urls>", "*://*/*", "http://*/*", "https://*/*"}


def assess(manifest: dict) -> tuple[str, list[str]]:
    """('danger' | 'caution', plain-language list of what the extension can do) from its manifest."""
    perms = [p for p in manifest.get("permissions", []) if isinstance(p, str)]
    hosts = [h for h in manifest.get("host_permissions", []) if isinstance(h, str)]
    for cs in manifest.get("content_scripts", []) or []:
        if isinstance(cs, dict):
            hosts += [m for m in cs.get("matches", []) if isinstance(m, str)]
    risks = []
    all_sites = any(h in _ALL_SITES or h.startswith("*://*") for h in hosts)
    if all_sites:
        risks.append("Read and change all your data on every website you visit")
    elif hosts:
        shown = sorted({re.sub(r"^\*?:?/*|/\*$", "", h) for h in hosts})[:5]
        risks.append("Read and change your data on: " + ", ".join(shown) + (" ..." if len(hosts) > 5 else ""))
    seen = set()
    for p in perms:
        txt = _PERMS.get(p)
        if txt and txt not in seen:
            seen.add(txt)
            risks.append(txt)
    high = all_sites and any(p in _HIGH for p in perms) or {"nativeMessaging", "debugger", "proxy"} & set(perms)
    return ("danger" if high else "caution"), risks


def library(lib: Path) -> list[dict]:
    """Every extension in the library: [{folder, path, name, description, version}], sorted by name."""
    out = []
    if lib.is_dir():
        for d in lib.iterdir():
            if d.is_dir() and not d.name.startswith(".") and (d / "manifest.json").is_file():
                try:
                    m = read_manifest(d)
                except ExtensionError:
                    continue
                out.append({"folder": d.name, "path": d, "name": localized(d, m, "name") or d.name,
                            "description": localized(d, m, "description"), "version": str(m.get("version", ""))})
    return sorted(out, key=lambda e: e["name"].lower())
