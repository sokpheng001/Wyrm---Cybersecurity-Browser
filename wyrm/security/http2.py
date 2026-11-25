#------------------------------------------------------------------------------
# Wyrm — wyrm/security/http2.py
# Developers: Kwan and Oda (intercepting HTTPS proxy — HTTP/2)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""HTTP/2 (h2) support for the intercepting proxy.

When the browser negotiates `h2` over ALPN, the proxy terminates HTTP/2 here (via hyper-h2) and runs each stream
through the *same* pipeline as HTTP/1.1 — a `fetch(req) -> result` callback that applies request rewriting,
interception, workflows, session handling and history, then forwards upstream over HTTP/1.1 and returns the
response. So intercept/edit/drop, Workflows and Session handling all work for h2 with no extra code.

Concurrency: a page opens many h2 streams at once, so each ended stream is served on its own worker thread. The
`fetch` upstream call (the slow part, and where interception blocks for user input) therefore never stalls the
other streams. The hyper-h2 `H2Connection` is not thread-safe, so every access to it — and every socket write —
happens under one lock; a worker waiting for the peer to open its flow-control window releases that lock and is
re-woken by the reader thread when a WINDOW_UPDATE arrives. A bounded worker pool protects the upstream.

Scope: client-side h2 is terminated; upstream is HTTP/1.1 (translation). WebSocket-over-h2 (RFC 8441) is not
handled — browsers still use HTTP/1.1 for WebSocket. HTTP/3 (QUIC) is out of scope.
"""
from __future__ import annotations

import threading

import h2.config
import h2.connection
import h2.errors
import h2.events
import h2.exceptions
import h2.settings

# response headers that are illegal or meaningless in HTTP/2, or that we recompute
_SKIP_RESP = {"connection", "transfer-encoding", "keep-alive", "proxy-connection", "upgrade",
              "content-length", "te", "trailer", "host"}

_MAX_CONCURRENT = 64          # streams we serve at once (also advertised to the client); bounds upstream load
_WINDOW_WAIT = 10.0          # seconds a body-send waits for a WINDOW_UPDATE before giving up on a stalled peer


class Http2Handler:
    """Serves one client HTTP/2 connection. `fetch(req)` returns the shared pipeline result dict.

    `fetch` is called from worker threads, so it (and everything it drives: interception prompts, workflows,
    history) must already be safe to run off the proxy's accept thread — the HTTP/1.1 path calls it the same way.
    """

    def __init__(self, sock, host, fetch, is_stopped):
        self.sock = sock
        self.host = host
        self.fetch = fetch
        self.is_stopped = is_stopped
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        self.conn = h2.connection.H2Connection(config=cfg)
        self.streams: dict[int, dict] = {}       # in-flight requests still arriving (reader thread only)
        self._reset: set[int] = set()            # stream ids the peer cancelled
        self._lock = threading.RLock()           # guards self.conn AND socket writes (h2 is not thread-safe)
        self._win = threading.Condition(self._lock)   # woken on WINDOW_UPDATE / settings change
        self._slots = threading.Semaphore(_MAX_CONCURRENT)   # bound concurrent upstream work
        self._workers: list[threading.Thread] = []

    # -------------------------------------------------- main loop (reader thread)
    def run(self):
        with self._lock:
            self.conn.initiate_connection()
            # tell the client how many streams we'll serve concurrently
            self.conn.update_settings({h2.settings.SettingCodes.MAX_CONCURRENT_STREAMS: _MAX_CONCURRENT})
            self._flush()
        try:
            while not self.is_stopped():
                try:
                    data = self.sock.recv(65536)
                except OSError:
                    break
                if not data:
                    break
                with self._lock:
                    try:
                        events = self.conn.receive_data(data)
                    except h2.exceptions.ProtocolError:
                        self._flush()
                        break
                    for event in events:
                        self._on_event(event)
                    self._flush()
                    self._win.notify_all()   # settings/flow-control may have advanced; wake any waiting senders
        finally:
            self._drain()

    def _on_event(self, event):
        """Dispatch one h2 event. Always called with self._lock held (from the reader thread)."""
        if isinstance(event, h2.events.RequestReceived):
            self.streams[event.stream_id] = {"headers": event.headers, "data": bytearray()}
        elif isinstance(event, h2.events.DataReceived):
            s = self.streams.get(event.stream_id)
            if s is not None:
                s["data"] += event.data
                self.conn.acknowledge_received_data(len(event.data), event.stream_id)
        elif isinstance(event, h2.events.StreamEnded):
            s = self.streams.pop(event.stream_id, None)
            if s is not None:
                self._spawn(event.stream_id, s)
        elif isinstance(event, h2.events.StreamReset):
            self.streams.pop(event.stream_id, None)
            self._reset.add(event.stream_id)        # tell a serving worker to stop
        elif isinstance(event, h2.events.ConnectionTerminated):
            self.streams.clear()

    # -------------------------------------------------- one request (worker thread)
    def _spawn(self, sid, s):
        t = threading.Thread(target=self._serve, args=(sid, s), daemon=True)
        self._workers.append(t)
        t.start()

    def _serve(self, sid, s):
        """Run one stream through the shared pipeline off the reader thread, then send its response."""
        if not self._slots.acquire(timeout=30):     # too many in flight: shed load rather than pile up
            self._reset_stream(sid)
            return
        try:
            if self.is_stopped() or sid in self._reset:
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
                   "headers": req_headers, "body": bytes(s["data"]), "client_proto": "h2"}
            res = self.fetch(req)                     # SLOW: upstream + interception. Deliberately off the lock.
            if self.is_stopped() or sid in self._reset:
                return
            if res.get("dropped"):
                self._reset_stream(sid)
            elif res.get("error"):
                self._respond(sid, 502, [("content-type", "text/plain; charset=utf-8")],
                              f"Wyrm proxy: upstream error: {res['error']}".encode())
            else:
                self._respond(sid, res["status"], res["headers"], res["body"])
        except Exception:  # noqa: BLE001 — one stream must never take down the connection
            self._reset_stream(sid)
        finally:
            self._slots.release()

    def _respond(self, sid, status, headers, body):
        body = body or b""
        resp_headers = [(":status", str(status))]
        for k, v in headers:
            if k.lower() in _SKIP_RESP:
                continue
            resp_headers.append((k.lower(), str(v)))
        resp_headers.append(("content-length", str(len(body))))
        with self._lock:
            if sid in self._reset:
                return
            try:
                self.conn.send_headers(sid, resp_headers, end_stream=not body)
                self._flush()
            except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError, OSError):
                return
        if body:
            self._send_body(sid, body)

    def _send_body(self, sid, body):
        pos, n = 0, len(body)
        while pos < n and not self.is_stopped():
            with self._lock:
                if sid in self._reset:
                    return
                try:
                    win = self.conn.local_flow_control_window(sid)
                except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError):
                    return
                if win <= 0:
                    # peer's flow-control window is closed — wait for the reader to see a WINDOW_UPDATE.
                    # _win.wait() releases the lock while blocked, so the reader can keep processing frames.
                    if not self._win.wait(timeout=_WINDOW_WAIT):
                        return
                    continue
                chunk = min(win, self.conn.max_outbound_frame_size, n - pos)
                end = (pos + chunk) >= n
                try:
                    self.conn.send_data(sid, body[pos:pos + chunk], end_stream=end)
                    self._flush()
                except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError, OSError):
                    return
                pos += chunk

    def _reset_stream(self, sid):
        with self._lock:
            try:
                self.conn.reset_stream(sid, error_code=h2.errors.ErrorCodes.CANCEL)
                self._flush()
            except (h2.exceptions.ProtocolError, h2.exceptions.StreamClosedError):
                pass

    def _flush(self):
        """Send everything hyper-h2 has queued. Caller must hold self._lock."""
        data = self.conn.data_to_send()
        if data:
            try:
                self.sock.sendall(data)
            except OSError:
                pass

    def _drain(self):
        """Connection is closing: wake any blocked senders and let workers finish briefly."""
        with self._lock:
            self._win.notify_all()
        for t in list(self._workers):
            if t is not threading.current_thread():
                t.join(timeout=2)
