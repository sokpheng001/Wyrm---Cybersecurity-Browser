#------------------------------------------------------------------------------
# Wyrm — wyrm/security/http2.py
# Developers: Kwan and Oda (intercepting HTTPS proxy — HTTP/2)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Sopi, Kwan
#------------------------------------------------------------------------------
"""HTTP/2 (h2) support for the intercepting proxy.

When the browser negotiates `h2` over ALPN, the proxy terminates HTTP/2 here (via hyper-h2) and runs each stream
through the *same* pipeline as HTTP/1.1 — a `fetch(req) -> result` callback that applies request rewriting,
interception, workflows, session handling and history, then forwards upstream over HTTP/1.1 and returns the
response. So intercept/edit/drop, Workflows and Session handling all work for h2 with no extra code.

v1 scope (experimental): client-side h2 is terminated; upstream is HTTP/1.1 (translation). Streams are handled
one at a time on the connection (correct, but not concurrently). WebSocket-over-h2 (RFC 8441) is not handled —
browsers still use HTTP/1.1 for WebSocket. HTTP/3 (QUIC) is out of scope.
"""
from __future__ import annotations

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions

# response headers that are illegal or meaningless in HTTP/2, or that we recompute
_SKIP_RESP = {"connection", "transfer-encoding", "keep-alive", "proxy-connection", "upgrade",
              "content-length", "te", "trailer", "host"}


class Http2Handler:
    """Serves one client HTTP/2 connection. `fetch(req)` returns the shared pipeline result dict."""

    def __init__(self, sock, host, fetch, is_stopped):
        self.sock = sock
        self.host = host
        self.fetch = fetch
        self.is_stopped = is_stopped
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        self.conn = h2.connection.H2Connection(config=cfg)
        self.streams: dict[int, dict] = {}

    # -------------------------------------------------- main loop
    def run(self):
        self.conn.initiate_connection()
        self._flush()
        while not self.is_stopped():
            try:
                data = self.sock.recv(65536)
            except OSError:
                break
            if not data:
                break
            try:
                events = self.conn.receive_data(data)
            except h2.exceptions.ProtocolError:
                self._flush()
                break
            for event in events:
                self._on_event(event)
            self._flush()

    def _on_event(self, event):
        if isinstance(event, h2.events.RequestReceived):
            self.streams[event.stream_id] = {"headers": event.headers, "data": bytearray()}
        elif isinstance(event, h2.events.DataReceived):
            s = self.streams.get(event.stream_id)
            if s is not None:
                s["data"] += event.data
                self.conn.acknowledge_received_data(len(event.data), event.stream_id)
        elif isinstance(event, h2.events.StreamEnded):
            self._handle_stream(event.stream_id)
        elif isinstance(event, h2.events.StreamReset):
            self.streams.pop(event.stream_id, None)
        elif isinstance(event, h2.events.ConnectionTerminated):
            self.streams.clear()

    # -------------------------------------------------- one request
    def _handle_stream(self, sid):
        s = self.streams.pop(sid, None)
        if s is None:
            return
        hdrs = s["headers"]
        pseudo = {k: v for k, v in hdrs if k.startswith(":")}
        method = pseudo.get(":method", "GET")
        path = pseudo.get(":path", "/")
        authority = pseudo.get(":authority") or self.host
        host = authority.split(":")[0]
        req_headers = [(k, v) for k, v in hdrs if not k.startswith(":")]
        if not any(k.lower() == "host" for k, _ in req_headers):   # HTTP/1.1 upstream needs a Host header
            req_headers.insert(0, ("Host", authority))
        req = {"scheme": "https", "host": host, "port": 443, "method": method, "path": path,
               "headers": req_headers, "body": bytes(s["data"])}
        res = self.fetch(req)
        if res.get("dropped"):
            self._reset(sid)
            return
        if res.get("error"):
            self._respond(sid, 502, [("content-type", "text/plain; charset=utf-8")],
                          f"Wyrm proxy: upstream error: {res['error']}".encode())
            return
        self._respond(sid, res["status"], res["headers"], res["body"])

    def _respond(self, sid, status, headers, body):
        body = body or b""
        resp_headers = [(":status", str(status))]
        for k, v in headers:
            if k.lower() in _SKIP_RESP:
                continue
            resp_headers.append((k.lower(), str(v)))
        resp_headers.append(("content-length", str(len(body))))
        try:
            self.conn.send_headers(sid, resp_headers, end_stream=not body)
            self._flush()
            if body:
                self._send_body(sid, body)
        except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError, OSError):
            return

    def _send_body(self, sid, body):
        pos, n = 0, len(body)
        while pos < n and not self.is_stopped():
            win = self.conn.local_flow_control_window(sid)
            if win <= 0:   # wait for the peer to open the flow-control window
                self._flush()
                try:
                    data = self.sock.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                for event in self.conn.receive_data(data):
                    self._on_event(event)
                continue
            chunk = min(win, self.conn.max_outbound_frame_size, n - pos)
            end = (pos + chunk) >= n
            self.conn.send_data(sid, body[pos:pos + chunk], end_stream=end)
            pos += chunk
            self._flush()

    def _reset(self, sid):
        try:
            self.conn.reset_stream(sid, error_code=h2.errors.ErrorCodes.CANCEL)
            self._flush()
        except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError):
            pass

    def _flush(self):
        data = self.conn.data_to_send()
        if data:
            try:
                self.sock.sendall(data)
            except OSError:
                pass
