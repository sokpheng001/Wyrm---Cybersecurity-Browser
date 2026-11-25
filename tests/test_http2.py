#------------------------------------------------------------------------------
# Wyrm — tests/test_http2.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Integration tests for the HTTP/2 side of the intercepting proxy (wyrm/security/http2.py).

A real hyper-h2 client drives the handler over a socketpair, so these exercise the true wire protocol:
  * concurrent streams are served in parallel (a slow upstream on one stream must not stall the others),
  * a large response body streams correctly across flow-control windows, and
  * a 'dropped' pipeline result resets the stream.
Run: `python -m pytest tests/test_http2.py` (or run this file directly)."""
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import h2.config          # noqa: E402
import h2.connection      # noqa: E402
import h2.events          # noqa: E402

from wyrm.security.http2 import Http2Handler  # noqa: E402


def _run_handler(server_sock, fetch):
    stop = {"v": False}
    h = Http2Handler(server_sock, "example.com", fetch, lambda: stop["v"])
    t = threading.Thread(target=h.run, daemon=True)
    t.start()
    return h, t, stop


class _Client:
    """Minimal client-side h2 driver over a plain socket."""

    def __init__(self, sock):
        self.sock = sock
        self.conn = h2.connection.H2Connection(
            config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8"))
        self.conn.initiate_connection()
        self._send()
        self.status: dict[int, int] = {}
        self.body: dict[int, bytearray] = {}
        self.ended: set[int] = set()
        self.reset: set[int] = set()

    def _send(self):
        data = self.conn.data_to_send()
        if data:
            self.sock.sendall(data)

    def request(self, path, body=b"", method="POST"):
        sid = self.conn.get_next_available_stream_id()
        headers = [(":method", method), (":authority", "example.com"), (":scheme", "https"),
                   (":path", path), ("content-length", str(len(body)))]
        self.conn.send_headers(sid, headers, end_stream=not body)
        if body:
            self.conn.send_data(sid, body, end_stream=True)
        self.body[sid] = bytearray()
        self._send()
        return sid

    def pump(self, want, timeout=10.0):
        """Read until `want` streams have ended or reset, or we time out."""
        self.sock.settimeout(timeout)
        deadline = time.time() + timeout
        while len(self.ended) + len(self.reset) < want and time.time() < deadline:
            try:
                data = self.sock.recv(65536)
            except (socket.timeout, OSError):
                break
            if not data:
                break
            for ev in self.conn.receive_data(data):
                if isinstance(ev, h2.events.ResponseReceived):
                    for k, v in ev.headers:
                        if k == ":status":
                            self.status[ev.stream_id] = int(v)
                elif isinstance(ev, h2.events.DataReceived):
                    self.body[ev.stream_id] += ev.data
                    self.conn.acknowledge_received_data(len(ev.data), ev.stream_id)   # open the window back up
                elif isinstance(ev, h2.events.StreamEnded):
                    self.ended.add(ev.stream_id)
                elif isinstance(ev, h2.events.StreamReset):
                    self.reset.add(ev.stream_id)
            self._send()


def _pair():
    a, b = socket.socketpair()
    return a, b


def test_streams_are_served_concurrently():
    DELAY, N = 0.3, 6

    def fetch(req):
        time.sleep(DELAY)   # simulate a slow upstream / blocking interception
        return {"status": 200, "reason": "OK", "headers": [("content-type", "text/plain")],
                "body": ("echo " + req["path"]).encode()}

    srv, cli = _pair()
    h, t, stop = _run_handler(srv, fetch)
    try:
        c = _Client(cli)
        t0 = time.time()
        ids = [c.request(f"/{i}", b"hi") for i in range(N)]
        c.pump(want=N)
        elapsed = time.time() - t0
        assert c.ended == set(ids), f"not all streams ended: {c.ended} vs {ids}"
        for i, sid in enumerate(ids):
            assert c.status[sid] == 200
            assert bytes(c.body[sid]) == f"echo /{i}".encode()
        # serial would be >= N*DELAY (1.8s); concurrent should finish in ~DELAY plus overhead
        assert elapsed < N * DELAY * 0.6, f"streams look serialized: {elapsed:.2f}s for {N} x {DELAY}s"
    finally:
        stop["v"] = True
        srv.close(); cli.close()


def test_large_body_streams_across_flow_control():
    payload = (b"ABCDEFGH" * 1024) * 40   # 320 KB — far past the 64 KB initial window, so it must wait/resume

    def fetch(req):
        return {"status": 200, "reason": "OK", "headers": [("content-type", "application/octet-stream")],
                "body": payload}

    srv, cli = _pair()
    h, t, stop = _run_handler(srv, fetch)
    try:
        c = _Client(cli)
        sid = c.request("/big", b"")
        c.pump(want=1, timeout=15)
        assert c.status.get(sid) == 200
        assert bytes(c.body[sid]) == payload, f"got {len(c.body[sid])} of {len(payload)} bytes"
    finally:
        stop["v"] = True
        srv.close(); cli.close()


def test_request_is_tagged_as_h2():
    seen = {}

    def fetch(req):
        seen.update(req)
        return {"status": 200, "reason": "OK", "headers": [], "body": b"ok"}

    srv, cli = _pair()
    h, t, stop = _run_handler(srv, fetch)
    try:
        c = _Client(cli)
        c.request("/p", b"x")
        c.pump(want=1)
        assert seen.get("client_proto") == "h2", "h2 streams must be tagged so the Proxy panel shows the protocol"
    finally:
        stop["v"] = True
        srv.close(); cli.close()


def test_dropped_request_resets_the_stream():
    def fetch(req):
        return {"dropped": True}

    srv, cli = _pair()
    h, t, stop = _run_handler(srv, fetch)
    try:
        c = _Client(cli)
        sid = c.request("/blocked", b"x")
        c.pump(want=1)
        assert sid in c.reset, "a dropped request should reset the stream"
        assert sid not in c.status
    finally:
        stop["v"] = True
        srv.close(); cli.close()


def test_upstream_error_returns_502():
    def fetch(req):
        return {"error": "connection refused"}

    srv, cli = _pair()
    h, t, stop = _run_handler(srv, fetch)
    try:
        c = _Client(cli)
        sid = c.request("/boom", b"x")
        c.pump(want=1)
        assert c.status.get(sid) == 502
        assert b"upstream error" in bytes(c.body[sid])
    finally:
        stop["v"] = True
        srv.close(); cli.close()


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
