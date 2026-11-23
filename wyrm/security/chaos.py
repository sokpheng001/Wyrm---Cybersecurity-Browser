#------------------------------------------------------------------------------
# Wyrm — wyrm/security/chaos.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Developer: Oda (ProjectDiscovery Chaos recon integration)
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""ProjectDiscovery Chaos: public bug-bounty recon data (https://chaos.projectdiscovery.io).

Passive and keyless: the public index lists ~800 bug-bounty programs (platform, bounty, subdomain count) and
each program has a zip of the subdomains Chaos has collected. Nothing here touches the target itself.

Downloaded archives are untrusted: size-capped, only ``.txt`` members are read, uncompressed size is checked
before extraction (zip-bomb guard), and only syntactically valid hostnames are kept.
"""
from __future__ import annotations

import io
import re
import time
import zipfile

import requests

INDEX_URL = "https://chaos-data.projectdiscovery.io/index.json"
UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Wyrm/1.0 (recon)"}
TIMEOUT = 25
INDEX_TTL = 6 * 3600              # re-download the index at most every 6 hours
MAX_ZIP_BYTES = 80 * 1024 * 1024  # refuse larger program archives
MAX_UNZIPPED = 400 * 1024 * 1024  # zip-bomb guard
MAX_HOSTS = 200_000
_HOST = re.compile(r"^(?=.{1,253}$)(\*\.)?([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

_index: dict = {"t": 0.0, "data": None}


def index(proxies=None, verify=True) -> list[dict]:
    """The public Chaos program index (cached in memory)."""
    if _index["data"] is not None and time.time() - _index["t"] < INDEX_TTL:
        return _index["data"]
    r = requests.get(INDEX_URL, headers=UA, timeout=TIMEOUT, proxies=proxies, verify=verify)
    r.raise_for_status()
    data = [p for p in r.json() if isinstance(p, dict) and p.get("name") and p.get("URL")]
    _index.update(t=time.time(), data=data)
    return data


def _base(q: str) -> str:
    """'https://www.tesla.com/x' -> 'tesla'; 'tesla' -> 'tesla'."""
    q = q.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    q = q.removeprefix("www.")
    parts = [p for p in q.split(".") if p]
    if len(parts) >= 2:  # drop the public suffix-ish tail (good enough for program-name matching)
        parts = parts[:-1] if len(parts[-1]) > 2 or len(parts) == 2 else parts[:-2]
    return "".join(parts[-1:]) if parts else q


def search(query: str, proxies=None, verify=True, limit: int = 25) -> list[dict]:
    """Programs whose name or program URL matches the query (program name or domain). Best matches first."""
    q = query.strip().lower()
    if not q:
        return []
    base = _base(q)
    hits = []
    for p in index(proxies, verify):
        name = p["name"].lower()
        url = (p.get("program_url") or "").lower()
        if name == base or name == q:
            score = 0
        elif name.startswith(base):
            score = 1
        elif base in name or ("." in q and (q in url or base in url)):  # url match only for domain queries
            score = 2
        else:
            continue
        hits.append((score, -(p.get("count") or 0), p))
    hits.sort(key=lambda h: (h[0], h[1]))
    return [{"name": p["name"], "platform": p.get("platform") or "self-hosted", "bounty": bool(p.get("bounty")),
             "count": int(p.get("count") or 0), "updated": (p.get("last_updated") or "")[:10],
             "program_url": p.get("program_url") or "", "zip": p["URL"]} for _s, _c, p in hits[:limit]]


def subdomains(program: dict, proxies=None, verify=True) -> list[str]:
    """All hostnames Chaos publishes for a program (from its zip), sorted and de-duplicated."""
    url = program["zip"]
    if not url.startswith("https://chaos-data.projectdiscovery.io/"):
        raise ValueError("Refusing to download from outside the Chaos dataset.")
    with requests.get(url, headers=UA, timeout=TIMEOUT, proxies=proxies, verify=verify, stream=True) as r:
        r.raise_for_status()
        buf = io.BytesIO()
        for chunk in r.iter_content(256 * 1024):
            buf.write(chunk)
            if buf.tell() > MAX_ZIP_BYTES:
                raise RuntimeError(f"This program's archive is larger than {MAX_ZIP_BYTES // 2**20} MB; "
                                   "download it from chaos.projectdiscovery.io instead.")
    hosts: set[str] = set()
    with zipfile.ZipFile(buf) as z:
        members = [i for i in z.infolist() if i.filename.lower().endswith(".txt") and not i.is_dir()]
        if sum(i.file_size for i in members) > MAX_UNZIPPED:
            raise RuntimeError("Archive expands to an unreasonable size; refusing to extract.")
        for i in members:
            for line in z.read(i).decode("utf-8", "replace").splitlines():
                h = line.strip().lower()
                if h and _HOST.match(h):
                    hosts.add(h)
                    if len(hosts) >= MAX_HOSTS:
                        return sorted(hosts)
    return sorted(hosts)
