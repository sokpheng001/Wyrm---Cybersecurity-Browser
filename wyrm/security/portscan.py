#------------------------------------------------------------------------------
# Wyrm — wyrm/security/portscan.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Developer: @kwan (port scanner: nmap or built-in)
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Port scanning for AUTHORIZED targets: uses nmap when installed, otherwise a built-in TCP connect scan.

The caller (Security panel → Scanner) only allows hosts inside the current engagement's scope. Scans are
polite: TCP connect only (no SYN/stealth/UDP tricks), the 100 most common ports, bounded concurrency and
timeouts. nmap runs as `nmap -sT -Pn --top-ports 100 -T3 [-sV]` and its XML output is parsed.
"""
from __future__ import annotations

import shutil
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

# the most common TCP ports (nmap's top ports, trimmed) with friendly names
TOP_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "http-alt", 88: "kerberos",
    110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps", 514: "shell", 515: "printer",
    548: "afp", 554: "rtsp", 587: "submission", 631: "ipp", 636: "ldaps", 873: "rsync", 990: "ftps",
    993: "imaps", 995: "pop3s", 1025: "nfs/iis", 1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1723: "pptp", 1883: "mqtt", 2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2181: "zookeeper",
    2375: "docker", 2376: "docker-tls", 3000: "dev-http", 3128: "squid", 3268: "ldap-gc", 3306: "mysql",
    3389: "rdp", 3690: "svn", 4000: "dev-http", 4443: "https-alt", 4848: "glassfish", 5000: "dev-http",
    5060: "sip", 5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc", 5984: "couchdb",
    6379: "redis", 6443: "kubernetes", 6667: "irc", 7001: "weblogic", 7443: "https-alt", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt", 8088: "http-alt", 8443: "https-alt",
    8500: "consul", 8888: "http-alt", 9000: "http-alt", 9090: "http-alt", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch", 9418: "git", 9999: "http-alt", 10000: "webmin", 11211: "memcached",
    15672: "rabbitmq", 27017: "mongodb", 50000: "sap",
}
RISKY = {23, 135, 139, 445, 1433, 2375, 3306, 3389, 5432, 5900, 5984, 6379, 9200, 11211, 27017}


def nmap_path() -> str | None:
    return shutil.which("nmap")


def _connect(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def builtin_scan(host: str, timeout: float = 1.0, workers: int = 32) -> list[dict]:
    ports = sorted(TOP_PORTS)
    with ThreadPoolExecutor(max_workers=workers) as ex:
        res = list(ex.map(lambda p: (p, _connect(host, p, timeout)), ports))
    return [{"port": p, "service": TOP_PORTS[p], "product": "", "risky": p in RISKY} for p, ok in res if ok]


def nmap_scan(host: str, versions: bool = False, timeout: int = 300) -> list[dict]:
    exe = nmap_path()
    if not exe:
        raise RuntimeError("nmap is not installed")
    cmd = [exe, "-sT", "-Pn", "--top-ports", "100", "-T3", "--max-retries", "1", "-oX", "-"]
    if versions:
        cmd.insert(2, "-sV")
    cmd.append(host)
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                         timeout=timeout, check=False,
                         creationflags=0x08000000 if sys.platform == "win32" else 0).stdout  # no console window
    rows = []
    for port in ET.fromstring(out).iter("port"):
        state = port.find("state")
        if state is None or state.get("state") != "open":
            continue
        svc = port.find("service")
        n = int(port.get("portid", 0))
        product = " ".join(x for x in ((svc.get("product") if svc is not None else ""),
                                       (svc.get("version") if svc is not None else "")) if x)
        rows.append({"port": n, "service": (svc.get("name") if svc is not None else "") or TOP_PORTS.get(n, ""),
                     "product": product, "risky": n in RISKY})
    return rows


def scan(host: str, use_nmap: bool = True, versions: bool = False) -> dict:
    """Open ports on `host` (top 100 TCP). Uses nmap if available and requested."""
    host = host.strip().lower()
    ip = socket.gethostbyname(host)  # resolves once; fails early for unknown hosts
    if use_nmap and nmap_path():
        return {"host": host, "ip": ip, "engine": "nmap", "open": nmap_scan(host, versions)}
    return {"host": host, "ip": ip, "engine": "built-in TCP connect", "open": builtin_scan(ip)}
