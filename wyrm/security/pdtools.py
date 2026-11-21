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
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
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
         ["-silent", "-json", "-a", "-aaaa", "-cname", "-resp", "-l", "{t}"], result_keys=("host", "a", "cname")),
    Tool("tlsx", "tlsx", "TLS certificate data (issuer, names, expiry)", True, "host",
         ["-silent", "-json", "-san", "-cn", "-u", "{t}"],
         result_keys=("host", "subject_cn", "issuer_cn")),
    Tool("naabu", "naabu", "Fast port scan (top ports) of a host", True, "host",
         ["-silent", "-json", "-top-ports", "100", "-host", "{t}"], result_keys=("port", "host")),
    Tool("httpx", "httpx", "Probe a host/URL: status, title, tech, server", True, "host",
         ["-silent", "-json", "-title", "-status-code", "-tech-detect", "-web-server", "-u", "{t}"],
         result_keys=("url", "status_code", "title", "webserver")),
    Tool("katana", "katana", "Crawl a site and list its URLs", True, "url",
         ["-silent", "-jsonl", "-d", "2", "-kf", "all", "-u", "{t}"], result_keys=("request.endpoint",)),
    Tool("nuclei", "nuclei", "Template-based vulnerability scan (safe/default templates)", True, "url",
         ["-silent", "-jsonl", "-u", "{t}"],
         result_keys=("template-id", "info.name", "matched-at", "info.severity")),
    Tool("cdncheck", "cdncheck", "Is the host behind a CDN / WAF / cloud?", True, "host",
         ["-silent", "-jsonl", "-resp", "-i", "{t}"], result_keys=("input", "ip", "cdn_name", "waf_name", "cloud_name")),
    Tool("uncover", "uncover", "Find exposed hosts via search engines (Shodan/Censys/Fofa keys)", False, "domain",
         ["-silent", "-json", "-q", "{t}"], result_keys=("ip", "port", "host")),
    Tool("mapcidr", "mapcidr", "Expand / aggregate a CIDR range into IPs", False, "cidr",
         ["-silent", "-cidr", "{t}"], result_keys=()),
    Tool("alterx", "alterx", "Generate subdomain permutation wordlist for a domain", False, "domain",
         ["-silent", "-enrich", "-l", "{t}"], result_keys=()),
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
    err = tempfile.TemporaryFile()  # stderr: kept so a failed run can say why (a pipe could fill up and block)
    try:
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=err, text=True,
                                # the tools print UTF-8; never decode with the Windows ANSI code page
                                encoding="utf-8", errors="replace",
                                # Windows: these are console programs; don't flash a terminal window per run
                                creationflags=0x08000000 if sys.platform == "win32" else 0)
    except OSError as e:
        err.close()
        raise RuntimeError(f"Could not start {tool.key}: {e}") from e

    # Stop / timeout must work even while the tool prints nothing for minutes (e.g. a long nuclei scan)
    state = {"why": None}
    done = threading.Event()

    def watch():
        deadline = time.monotonic() + timeout
        while not done.wait(0.4):
            why = "stopped" if should_stop and should_stop() else "timeout" if time.monotonic() > deadline else None
            if why:
                state["why"] = why
                proc.kill()
                return
    threading.Thread(target=watch, daemon=True).start()
    try:
        if stdin_data:
            proc.stdin.write(stdin_data)
            proc.stdin.close()
        for line in proc.stdout:
            line = line.strip()
            if not line or state["why"]:
                continue
            if "API Key" in line and ("Enter" in line or "exit to abort" in line):  # waiting for a key prompt
                state["why"] = "needs-key"
                proc.kill()
                continue
            obj = None
            if line.startswith("{"):
                try:
                    obj = json.loads(line)
                except ValueError:
                    obj = None
            on_line(summarize(tool, obj) if obj else line, obj)
            count += 1
        proc.wait()
    finally:
        done.set()
        if proc.poll() is None:
            proc.kill()
    if state["why"] == "needs-key":
        err.close()
        raise RuntimeError(f"{tool.key} needs a free ProjectDiscovery Cloud API key (cloud.projectdiscovery.io). "
                           f"Set it once with “{tool.key} -auth” in a terminal, or the PDCP_API_KEY environment "
                           "variable, then restart Wyrm.")
    if state["why"]:
        err.close()
        return {"tool": tool.key, "count": count, "stopped": state["why"]}
    err.seek(0)
    tail = err.read()[-4000:].decode("utf-8", "replace")
    err.close()
    if proc.returncode and not count:
        raise RuntimeError(f"{tool.key} exited with code {proc.returncode}: {_last_error(tail)}")
    return {"tool": tool.key, "count": count, "stopped": None}


def _last_error(stderr: str) -> str:
    """The most useful line of a tool's stderr: its last error/fatal line, else its last line. ANSI colours and
    ProjectDiscovery's banner art are stripped."""
    lines = [re.sub(r"\x1b\[[0-9;]*m", "", ln).strip() for ln in stderr.splitlines()]
    art = set(" _/\\|`'.,-()<>=")
    lines = [ln for ln in lines if ln and not set(ln) <= art]
    for ln in reversed(lines):
        if re.search(r"(?i)\b(err|error|fatal|ftl|could not|failed|panic)\b", ln):
            return ln[:300]
    return lines[-1][:300] if lines else "no error message"
