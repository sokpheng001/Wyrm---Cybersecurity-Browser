#------------------------------------------------------------------------------
# Wyrm — wyrm/bgserver.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Tiny loopback HTTP server for the start-page background VIDEO.

Qt WebEngine's <video> element can't play media from a custom wyrm:// scheme (the media pipeline needs HTTP
range requests / 206 responses). So an uploaded video is served from 127.0.0.1 with full Range support, and the
start page points <video> at http://127.0.0.1:<port>/bgvideo. Bound to loopback only, serves just one file.
"""
from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_CTYPE = {".mp4": "video/mp4", ".m4v": "video/mp4", ".webm": "video/webm", ".mov": "video/quicktime"}


class _Handler(BaseHTTPRequestHandler):
    def _file(self):
        return self.server.current_file()  # -> Path | None

    def do_HEAD(self):
        self._serve(head_only=True)

    def do_GET(self):
        self._serve(head_only=False)

    def _serve(self, head_only: bool):
        if self.path.split("?")[0] != "/bgvideo":
            self.send_error(404)
            return
        f = self._file()
        if not f or not Path(f).is_file():
            self.send_error(404)
            return
        f = Path(f)
        size = f.stat().st_size
        ctype = _CTYPE.get(f.suffix.lower(), "application/octet-stream")
        start, end = 0, size - 1
        rng = self.headers.get("Range")
        partial = False
        if rng and rng.startswith("bytes="):
            try:
                s, _, e = rng[6:].partition("-")
                start = int(s) if s else 0
                end = int(e) if e else size - 1
                end = min(end, size - 1)
                partial = 0 <= start <= end
            except ValueError:
                partial = False
        try:
            if partial:
                self.send_response(206)
                self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
            else:
                self.send_response(200)
                start, end = 0, size - 1
            length = end - start + 1
            self.send_header("Content-Type", ctype)
            self.send_header("Accept-Ranges", "bytes")
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if head_only:
                return
            with open(f, "rb") as fh:
                fh.seek(start)
                remaining = length
                while remaining > 0:
                    chunk = fh.read(min(256 * 1024, remaining))
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    remaining -= len(chunk)
        except (BrokenPipeError, ConnectionError, OSError):
            pass  # the media element closed the connection (normal when seeking/looping)

    def log_message(self, *a):
        pass


class BackgroundVideoServer:
    """Starts on first use; serves whatever current_file() returns at http://127.0.0.1:<port>/bgvideo."""

    def __init__(self, current_file):
        self._current_file = current_file
        self._srv: ThreadingHTTPServer | None = None
        self.port = 0

    def url(self) -> str:
        if self._srv is None:
            self._start()
        return f"http://127.0.0.1:{self.port}/bgvideo" if self.port else ""

    def _start(self):
        try:
            self._srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
            self._srv.current_file = self._current_file  # read by the handler
            self._srv.daemon_threads = True
            self.port = self._srv.server_address[1]
            threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        except OSError:
            self._srv, self.port = None, 0

    def stop(self):
        if self._srv is not None:
            try:
                self._srv.shutdown()
                self._srv.server_close()
            except OSError:
                pass
            self._srv, self.port = None, 0
