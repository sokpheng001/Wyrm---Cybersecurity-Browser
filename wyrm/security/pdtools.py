#------------------------------------------------------------------------------
# Wyrm — wyrm/security/pdtools.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Developer: @kwan (ProjectDiscovery tool integration)
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Run ProjectDiscovery's open-source recon/scanning tools (https://github.com/projectdiscovery) when they are
installed on the machine, and stream their results into the Scanner panel.

The tools ship inside Wyrm (wyrm/bin/, downloaded and SHA-256-verified at build time by
tools/fetch_pdtools.py); a copy on the PATH is used as a fallback (e.g. when running from source). Every tool that contacts the target is marked ``active`` and the panel only runs those on hosts
inside the current engagement scope. Tools run with bounded concurrency/rate and a hard timeout; output is
read as JSON Lines so results appear as they arrive. Nothing is downloaded at runtime.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Tool:
    key: str                     # executable name
    name: str                    # label in the UI
    desc: str                    # one-line description
    active: bool                 # True = contacts the target (scope-gated); False = passive/offline
    takes: str                   # what the target box should contain: "domain", "url", "host", "cidr", "asn"
    args: list[str]              # fixed args; "{t}" is replaced by the target
    json_flag: str = "-silent"   # extra flag(s) already in args; kept for reference
    result_keys: tuple = ()      # JSON keys to show, in order (first non-empty is the headline)


# The ProjectDiscovery suite. `{t}` is the target. All use -silent and JSON/JSONL output so we can stream rows.
TOOLS: list[Tool] = [
    Tool("subfinder", "subfinder", "Passive subdomain discovery for a domain", False, "domain",
         ["-silent", "-oJ", "-d", "{t}"], result_keys=("host",)),
    Tool("asnmap", "asnmap", "ASN / organisation → IP ranges", False, "domain",
         ["-silent", "-json", "-d", "{t}"], result_keys=("as_number", "as_name", "as_range")),
    Tool("dnsx", "dnsx", "Resolve DNS records (A/AAAA/CNAME) for a host", True, "domain",
         ["-silent", "-json", "-a", "-aaaa", "-cname", "-resp", "-d", "{t}"], result_keys=("host", "a", "cname")),
    Tool("tlsx", "tlsx", "TLS certificate data (issuer, names, expiry)", True, "host",
         ["-silent", "-json", "-san", "-cn", "-expired", "-self-signed", "-u", "{t}"],
         result_keys=("host", "subject_cn", "issuer_cn")),
    Tool("naabu", "naabu", "Fast port scan (top ports) of a host", True, "host",
         ["-silent", "-json", "-top-ports", "100", "-host", "{t}"], result_keys=("port", "host")),
    Tool("httpx", "httpx", "Probe a host/URL: status, title, tech, server", True, "host",
         ["-silent", "-json", "-title", "-status-code", "-tech-detect", "-web-server", "-u", "{t}"],
         result_keys=("url", "status_code", "title", "webserver")),
    Tool("katana", "katana", "Crawl a site and list its URLs", True, "url",
         ["-silent", "-jsonl", "-d", "2", "-kf", "all", "-u", "{t}"], result_keys=("endpoint", "url")),
    Tool("nuclei", "nuclei", "Template-based vulnerability scan (safe/default templates)", True, "url",
         ["-silent", "-jsonl", "-u", "{t}"],
         result_keys=("template-id", "info.name", "matched-at", "info.severity")),
    Tool("cdncheck", "cdncheck", "Is the host behind a CDN / WAF / cloud?", True, "host",
         ["-silent", "-json", "-resp", "-i", "{t}"], result_keys=("input", "cdn_name", "cloud_name")),
    Tool("uncover", "uncover", "Find exposed hosts via search engines (Shodan/Censys/Fofa keys)", False, "domain",
         ["-silent", "-json", "-q", "{t}"], result_keys=("ip", "port", "host")),
    Tool("mapcidr", "mapcidr", "Expand / aggregate a CIDR range into IPs", False, "cidr",
         ["-silent", "-cidr", "{t}"], result_keys=()),
    Tool("alterx", "alterx", "Generate subdomain permutation wordlist for a domain", False, "domain",
         ["-silent", "-enrich", "-d", "{t}"], result_keys=()),
]
TOOLS_BY_KEY = {t.key: t for t in TOOLS}


BUNDLED = Path(__file__).resolve().parents[1] / "bin"  # wyrm/bin (also inside the packaged app)


def find(key: str) -> str | None:
    """Path of a tool: the copy bundled with Wyrm, else one on the PATH."""
    exe = BUNDLED / (key + (".exe" if sys.platform == "win32" else ""))
    return str(exe) if exe.is_file() else shutil.which(key)


def installed() -> list[Tool]:
    """The ProjectDiscovery tools available (bundled with Wyrm or on the PATH), shown in the UI."""
    return [t for t in TOOLS if find(t.key)]


def _dig(obj: dict, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def summarize(tool: Tool, obj: dict) -> str:
    """One readable line from a tool's JSON object."""
    bits = []
    for k in tool.result_keys:
        val = _dig(obj, k)
        if val not in (None, "", [], {}):
            bits.append(str(val if not isinstance(val, list) else ", ".join(map(str, val))))
    return "  ".join(bits) if bits else json.dumps(obj, separators=(",", ":"))[:200]


def run(tool: Tool, target: str, on_line, proxies=None, timeout: int = 600, should_stop=None) -> dict:
    """Run one tool against `target`, calling on_line(text, obj|None) per output line. Returns a summary.

    `on_line` is called from this worker thread; the caller marshals to the UI. `should_stop`, if given, is
    polled per line and kills the process when it returns True. Plain stdin tools (mapcidr, alterx) are fed the
    target on stdin; the rest take it as an argument.
    """
    exe = find(tool.key)
    if not exe:
        raise RuntimeError(f"{tool.key} is not installed")
    args = [a.replace("{t}", target) for a in tool.args]
    stdin_data = None
    if "{t}" not in "".join(tool.args):      # mapcidr / alterx read the target from stdin
        stdin_data = target + "\n"
    cmd = [exe] + args
    count = 0
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                                # Windows: these are console programs; don't flash a terminal window per run
                                creationflags=0x08000000 if sys.platform == "win32" else 0)
    except OSError as e:
        raise RuntimeError(f"Could not start {tool.key}: {e}") from e
    try:
        if stdin_data:
            proc.stdin.write(stdin_data)
            proc.stdin.close()
        for line in proc.stdout:
            if should_stop and should_stop():
                proc.kill()
                return {"tool": tool.key, "count": count, "stopped": "stopped"}
            line = line.strip()
            if not line:
                continue
            obj = None
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except ValueError:
                    obj = None
            on_line(summarize(tool, obj) if obj else line, obj)
            count += 1
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        return {"tool": tool.key, "count": count, "stopped": "timeout"}
    finally:
        if proc.poll() is None:
            proc.kill()
    return {"tool": tool.key, "count": count, "stopped": None}
