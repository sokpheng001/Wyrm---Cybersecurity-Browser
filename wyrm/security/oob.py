#------------------------------------------------------------------------------
# Wyrm — wyrm/security/oob.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Developer: @kwan (out-of-band interaction listener)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Out-of-band (OOB) interaction listener — a Collaborator-style HTTP callback catcher.

Confirms blind vulnerabilities (blind SSRF, blind XSS, SSTI, XXE, command injection with an HTTP callback) by
giving you a unique URL to inject. When the target (or a victim's browser) fetches that URL, Wyrm records the
hit: time, source IP, method, path, headers, body, user-agent.

Scope / honesty: this is an HTTP listener on *your* machine. It catches callbacks only from hosts that can
reach it — your LAN / internal targets, or any target on the internet when Wyrm runs on a public IP or you
port-forward. It is not a hosted public Collaborator and does not do DNS-only OOB. Configure the public address
(your reachable host/IP and port) in the panel so the generated URLs point where targets can actually reach you.
"""
from __future__ import annotations

import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# A tiny 1x1 transparent GIF, returned for callbacks (so a blind-XSS <img> beacon loads cleanly).
_GIF = (b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x01\x00\x00\x00\x00,"
        b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record(self):
        body = b""
        try:
            n = int(self.headers.get("Content-Length", 0) or 0)
            if 0 < n <= 1_000_000:
                body = self.rfile.read(n)
        except (ValueError, OSError):
            pass
        hit = {
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
            "ip": self.client_address[0],
            "method": self.command,
            "path": self.path,
            "ua": self.headers.get("User-Agent", ""),
            "headers": {k: v for k, v in self.headers.items()},
            "body": body.decode("utf-8", "replace")[:2000],
        }
        self.server.on_hit(hit)
        out = _GIF
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Content-Length", str(len(out)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = do_DELETE = _record

    def log_message(self, *a):
        pass


class InteractionServer:
    """Listens on all interfaces (configurable port) and reports each callback via on_hit(dict)."""

    def __init__(self, on_hit):
        self._on_hit = on_hit
        self._srv: ThreadingHTTPServer | None = None
        self.port = 0

    def start(self, port: int = 0, bind: str = "0.0.0.0") -> bool:
        if self._srv is not None:
            return True
        try:
            self._srv = ThreadingHTTPServer((bind, port), _Handler)
            self._srv.on_hit = self._on_hit
            self._srv.daemon_threads = True
            self.port = self._srv.server_address[1]
            threading.Thread(target=self._srv.serve_forever, daemon=True).start()
            return True
        except OSError:
            self._srv, self.port = None, 0
            return False

    def stop(self):
        if self._srv is not None:
            try:
                self._srv.shutdown()
                self._srv.server_close()
            except OSError:
                pass
            self._srv, self.port = None, 0

    @staticmethod
    def new_token() -> str:
        """A short unique marker to put in a payload and recognise in the callback path."""
        return secrets.token_hex(5)


def local_ips() -> list[str]:
    """Best-effort list of this machine's LAN IPs, to suggest a reachable address for payloads."""
    import socket
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if "." in ip and not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass
    try:  # the IP used to reach the internet (route lookup, no packets sent)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.add(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    return sorted(ips)
