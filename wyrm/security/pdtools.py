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


_PORT_AWARE = {"httpx", "tlsx", "naabu", "cdncheck"}  # host tools that accept host:port
_CIDR_AWARE = {"naabu", "httpx", "tlsx"}               # host tools that scan a whole IP range


def target_for(tool: Tool, text: str) -> str:
    """What `tool` should receive for whatever the user typed: a domain, URL, host:port, IP, CIDR, ASN...
    Raises ValueError with a readable message when the input can't fit this tool. URL tools get a URL; when the
    user typed no scheme the result starts with "?//" and probe_scheme() picks https or http before running."""
    import ipaddress
    from urllib.parse import urlsplit
    raw = (text or "").strip().strip("'\"").rstrip("/")
    if not raw:
        raise ValueError("Enter a target first (a domain, URL or IP).")
    if tool.takes == "cidr":
        try:
            return str(ipaddress.ip_network(raw, strict=False))
        except ValueError:
            raise ValueError(f"{tool.name} needs an IP range like 192.168.1.0/24, not “{raw}”.") from None
    if tool.takes == "asn":
        m = re.fullmatch(r"(?i)(?:AS)?(\d{1,10})", raw)
        if not m:
            raise ValueError(f"{tool.name} needs an AS number like AS13335, not “{raw}”.")
        return "AS" + m.group(1)
    if re.fullmatch(r"(?i)AS\d{1,10}", raw):
        raise ValueError(f"{raw.upper()} is an AS number; {tool.name} needs a domain, host or URL.")
    if "/" in raw and "://" not in raw:  # an IP range?
        try:
            net = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            net = None
        if net is not None:
            if tool.key in _CIDR_AWARE:
                return str(net)
            raise ValueError(f"{tool.name} doesn't take an IP range; enter one host, domain or URL "
                             "(naabu, httpx and tlsx can scan a range).")
    has_scheme = "://" in raw
    parts = urlsplit(raw if has_scheme else "//" + raw)
    if has_scheme and parts.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Only http:// and https:// targets are supported, not {parts.scheme}://.")
    try:
        host = (parts.hostname or "").rstrip(".").lower()
        port = parts.port
    except ValueError:
        raise ValueError(f"“{raw}” isn't a valid host or URL.") from None
    if host.startswith("*."):
        host = host[2:]
    if not host or not re.fullmatch(r"[a-z0-9._:-]+", host):
        raise ValueError(f"“{raw}” isn't a valid domain, host or URL.")
    try:
        is_ip = bool(ipaddress.ip_address(host))
    except ValueError:
        is_ip = False
    hostport = (f"[{host}]" if ":" in host else host) + (f":{port}" if port else "")
    if tool.takes == "domain":
        if is_ip:
            raise ValueError(f"{tool.name} works on domain names; “{host}” is an IP address.")
        return host
    if tool.takes == "host":
        if tool.key == "httpx" and has_scheme:  # httpx probes URLs too: keep the scheme and path the user typed
            return f"{parts.scheme.lower()}://{hostport}{parts.path or ''}"
        return hostport if tool.key in _PORT_AWARE else host
    # url tools: keep the path the user typed; scheme decided now or by probe_scheme()
    path = parts.path or ""
    query = f"?{parts.query}" if parts.query else ""
    return (f"{parts.scheme.lower()}://" if has_scheme else "?//") + hostport + path + query


def probe_scheme(target: str, proxies=None) -> str:
    """For a URL target typed without a scheme ("?//host/..."): https if the site answers on it, else http.
    Certificates aren't checked here: a site with a self-signed certificate still speaks https."""
    if not target.startswith("?//"):
        return target
    import requests
    rest = target[3:]
    import warnings
    for scheme in ("https", "http"):
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")  # unverified-certificate warning: only reachability matters here
                requests.head(f"{scheme}://{rest}", timeout=6, allow_redirects=False, proxies=proxies, verify=False)
            return f"{scheme}://{rest}"
        except requests.RequestException:
            continue
    return f"https://{rest}"  # neither answered: let the tool report it


BUNDLED = Path(__file__).resolve().parents[1] / "bin"  # wyrm/bin (also inside the packaged app)
USER_DIR: "Path | None" = None  # writable dir for auto-updated tools (set by the window); checked before BUNDLED


def find(key: str) -> str | None:
    """Path of a tool: an auto-updated copy if present, else the one bundled with Wyrm, else one on the PATH."""
    exe_name = key + (".exe" if sys.platform == "win32" else "")
    if USER_DIR is not None:
        upd = USER_DIR / "pdtools" / exe_name
        if upd.is_file():
            return str(upd)
    exe = BUNDLED / "pdtools" / exe_name
    return str(exe) if exe.is_file() else shutil.which(key)


def templates_dir() -> "Path | None":
    """nuclei templates: an auto-updated copy if present, else the bundled one."""
    if USER_DIR is not None and (USER_DIR / "nuclei-templates").is_dir():
        return USER_DIR / "nuclei-templates"
    b = BUNDLED / "nuclei-templates"
    return b if b.is_dir() else None


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
    if tool.key == "nuclei":  # use the templates bundled with (or auto-updated by) Wyrm, offline
        tpl = templates_dir()
        if tpl is not None:
            args = ["-disable-update-check", "-t", str(tpl)] + args
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


# Wappalyzer-style technology detection, built in: the bundled httpx's -tech-detect uses wappalyzergo
# (MIT, ProjectDiscovery) with the open-source Wappalyzer fingerprint set. One request, like opening the page.
TECH_TOOL = Tool("httpx", "Technologies", "What a website is built with (Wappalyzer-style)", False, "url",
                 ["-silent", "-json", "-tech-detect", "-title", "-status-code", "-web-server", "-cdn",
                  "-follow-redirects", "-u", "{t}"])


def detect_technologies(url: str, proxies=None, should_stop=None) -> dict:
    """{url, final_url, status, title, server, cdn, tech: [(name, version)]} for one page."""
    rows = []
    res = run(TECH_TOOL, url, lambda _t, obj: rows.append(obj) if obj else None, proxies=proxies,
              timeout=60, should_stop=should_stop)
    if res.get("stopped"):
        raise RuntimeError(f"Technology detection {res['stopped']}.")
    if not rows:
        raise RuntimeError("The site didn't answer (or blocked the request).")
    o = rows[-1]
    tech = []
    for t in o.get("tech") or []:
        name, _, ver = str(t).partition(":")
        tech.append((name.strip(), ver.strip()))
    return {"url": url, "final_url": o.get("final_url") or o.get("url") or url, "status": o.get("status_code"),
            "title": o.get("title") or "", "server": o.get("webserver") or "",
            "cdn": o.get("cdn_name") or "", "tech": sorted(tech, key=lambda x: x[0].lower())}


def detect_from_page(html: str, headers: dict, page_url: str, should_stop=None) -> dict:
    """Technologies of a page the user has OPEN: its real HTML (from the tab) and response headers are served to
    the bundled httpx on a throw-away 127.0.0.1 server, so the Wappalyzer fingerprints see exactly what the
    browser received (past bot checks / logins), and the site is not contacted again."""
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    body = html.encode("utf-8", "replace")
    skip = {"content-length", "content-encoding", "transfer-encoding", "connection", "keep-alive",
            "strict-transport-security", "location"}
    server_hdr = next((str(v) for k, v in (headers or {}).items() if k.lower() == "server"), "")
    keep = [(k, v) for k, v in (headers or {}).items() if k.lower() not in skip and k.lower() != "server"]

    class Page(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            for k, v in keep:
                for part in str(v).splitlines():   # several Set-Cookie values arrive joined by newlines
                    self.send_header(k, part)
            if not any(k.lower() == "content-type" for k, _ in keep):
                self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

        def version_string(self):  # pass on the site's own Server header, not "BaseHTTP/... Python/3.x"
            return server_hdr

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Page)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        local = f"http://127.0.0.1:{srv.server_address[1]}/"
        tool = Tool("httpx", "Technologies", "", False, "url",
                    ["-silent", "-json", "-tech-detect", "-title", "-status-code", "-web-server", "-u", "{t}"])
        rows = []
        res = run(tool, local, lambda _t, obj: rows.append(obj) if obj else None, timeout=60, should_stop=should_stop)
        if res.get("stopped"):
            raise RuntimeError(f"Technology detection {res['stopped']}.")
        o = rows[-1] if rows else {}
    finally:
        srv.shutdown()
        srv.server_close()
    tech = []
    for t in o.get("tech") or []:
        name, _, ver = str(t).partition(":")
        tech.append((name.strip(), ver.strip()))
    server = next((v for k, v in (headers or {}).items() if k.lower() == "server"), "")
    return {"url": page_url, "final_url": page_url, "status": 200, "title": o.get("title") or "",
            "server": server, "cdn": "", "tech": sorted(tech, key=lambda x: x[0].lower()), "from_page": True}
