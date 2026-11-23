#------------------------------------------------------------------------------
# Wyrm — wyrm/security/mitm.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Developers: Kwan and Oda (intercepting HTTPS proxy)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""A local intercepting HTTPS proxy (Burp/Caido-style) for Wyrm's own traffic.

Chromium is pointed at this proxy (127.0.0.1). For https, Chromium sends CONNECT; the proxy terminates TLS with
a per-host certificate signed by a local CA, reads the plaintext HTTP, forwards it upstream, and relays the
response — capturing the full request and response (with bodies). A flow can optionally be paused so the user
edits the response before it reaches the page (response interception).

Scope: this only touches the user's own browser traffic, for authorized testing. The CA lives in the user's
profile and is trusted only by this user; it is removed when proxy capture is turned off.
"""
from __future__ import annotations

import gzip
import io
import socket
import ssl
import threading
import time
import zlib
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


# ---------------------------------------------------------------- certificate authority
class CertAuthority:
    """A local CA that mints per-host leaf certificates on demand (cached in memory)."""

    def __init__(self, cert_dir: Path):
        self.dir = cert_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = self.dir / "wyrm-ca.pem"
        self.ca_key_path = self.dir / "wyrm-ca.key"
        self._leaf_cache: dict[str, ssl.SSLContext] = {}
        self._ca_cert, self._ca_key = self._load_or_make_ca()

    def _load_or_make_ca(self):
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            try:
                cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
                key = serialization.load_pem_private_key(self.ca_key_path.read_bytes(), password=None)
                return cert, key
            except Exception:  # noqa: BLE001 - regenerate on any problem
                pass
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "Wyrm Browser Local CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ByKh R&D Group (Wyrm)"),
        ])
        now = _utcnow()
        cert = (x509.CertificateBuilder()
                .subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - _days(1)).not_valid_after(now + _days(3650))
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                             key_encipherment=False, content_commitment=False,
                                             data_encipherment=False, key_agreement=False,
                                             encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .sign(key, hashes.SHA256()))
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.ca_key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        return cert, key

    def context_for(self, host: str, alpn_h2: bool = False) -> ssl.SSLContext:
        """A server-side SSLContext presenting a cert for `host`, signed by our CA (cached per host).
        When alpn_h2 is set, HTTP/2 is offered over ALPN (h2) ahead of HTTP/1.1."""
        cache_key = (host, alpn_h2)
        if cache_key in self._leaf_cache:
            return self._leaf_cache[cache_key]
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        try:
            san = x509.IPAddress(__import__("ipaddress").ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        now = _utcnow()
        cert = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
                .issuer_name(self._ca_cert.subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(now - _days(1)).not_valid_after(now + _days(825))
                .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
                .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._ca_key.public_key()),
                               critical=False)
                .sign(self._ca_key, hashes.SHA256()))
        import tempfile
        fd = tempfile.NamedTemporaryFile(delete=False, suffix=".pem")
        fd.write(cert.public_bytes(serialization.Encoding.PEM))
        fd.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                   serialization.NoEncryption()))
        fd.close()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(fd.name)
        try:
            Path(fd.name).unlink()
        except OSError:
            pass
        ctx.set_alpn_protocols(["h2", "http/1.1"] if alpn_h2 else ["http/1.1"])
        self._leaf_cache[cache_key] = ctx
        return ctx


_UPSTREAM_CTX = None


def _upstream_ctx():
    """TLS context for connecting to real servers. Uses certifi's CA bundle so verification works in a frozen
    build and in venvs that don't expose the OS trust store."""
    global _UPSTREAM_CTX
    if _UPSTREAM_CTX is None:
        try:
            import certifi
            _UPSTREAM_CTX = ssl.create_default_context(cafile=certifi.where())
        except Exception:  # noqa: BLE001
            _UPSTREAM_CTX = ssl.create_default_context()
    return _UPSTREAM_CTX


ACTIVE: "MitmProxy | None" = None  # the running proxy (set at startup), picked up by the window


def start_if_enabled(data_dir: Path):
    """Called at startup (before QApplication): if the intercepting proxy is on, start it and return the
    Chromium --proxy-server flags to route the browser through it. Returns [] when off."""
    global ACTIVE
    from PySide6.QtCore import QSettings
    if not QSettings().value("mitm/enabled", False, type=bool):
        return []
    try:
        ca = CertAuthority(data_dir / "mitm")
        proxy = MitmProxy(ca)
        proxy.http2 = QSettings().value("mitm/http2", False, type=bool)   # experimental; off by default
        port = proxy.start(0)
        ACTIVE = proxy
        return [f"--proxy-server=127.0.0.1:{port}", "--proxy-bypass-list=<-loopback>"]
    except Exception:  # noqa: BLE001 - never block startup over the proxy
        ACTIVE = None
        return []


def install_ca(ca_pem: Path) -> bool:
    """Trust the local CA for this user so the browser accepts the proxy's certificates (no admin needed)."""
    import subprocess
    import sys
    try:
        if sys.platform == "win32":
            r = subprocess.run(["certutil", "-addstore", "-user", "-f", "Root", str(ca_pem)],
                               capture_output=True, timeout=30,
                               creationflags=0x08000000)
            return r.returncode == 0
        if sys.platform == "darwin":
            r = subprocess.run(["security", "add-trusted-cert", "-d", "-r", "trustRoot",
                                "-k", str(Path.home() / "Library/Keychains/login.keychain-db"), str(ca_pem)],
                               capture_output=True, timeout=30)
            return r.returncode == 0
        # Linux: trust stores vary; copy into the user NSS db if certutil (libnss3-tools) is present
        return False
    except (OSError, subprocess.SubprocessError):
        return False


def uninstall_ca() -> None:
    import subprocess
    import sys
    try:
        if sys.platform == "win32":
            subprocess.run(["certutil", "-delstore", "-user", "Root", "Wyrm Browser Local CA"],
                           capture_output=True, timeout=30, creationflags=0x08000000)
        elif sys.platform == "darwin":
            subprocess.run(["security", "delete-certificate", "-c", "Wyrm Browser Local CA"],
                           capture_output=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        pass


def _utcnow():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _days(n):
    from datetime import timedelta
    return timedelta(days=n)


# ---------------------------------------------------------------- HTTP helpers
def _recv_headers(f):
    """Read request/response line + headers from a buffered file; returns (first_line, header_lines) or None."""
    line = f.readline()
    if not line:
        return None
    first = line.rstrip(b"\r\n")
    headers = []
    while True:
        h = f.readline()
        if h in (b"\r\n", b"\n", b""):
            break
        headers.append(h.rstrip(b"\r\n"))
    return first, headers


def _read_head_raw(sock):
    """Read the request line + headers straight from the socket WITHOUT reading past the blank line (so the TLS
    ClientHello after a CONNECT isn't swallowed). Returns (first_line, header_lines, leftover_bytes) or None."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        try:
            chunk = sock.recv(4096)
        except OSError:
            return None
        if not chunk:
            if not buf:
                return None
            break
        buf += chunk
        if len(buf) > 262144:  # absurd header size
            break
    head, _, leftover = buf.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        return None
    return lines[0], lines[1:], leftover


class _Prebuffered:
    """A minimal readline()/read() reader over a socket, starting with already-received bytes."""
    def __init__(self, sock, initial=b""):
        self._sock = sock
        self._buf = initial

    def _fill(self):
        try:
            d = self._sock.recv(65536)
        except OSError:
            return False
        if not d:
            return False
        self._buf += d
        return True

    def readline(self):
        while b"\n" not in self._buf:
            if not self._fill():
                break
        i = self._buf.find(b"\n")
        if i < 0:
            line, self._buf = self._buf, b""
            return line
        line, self._buf = self._buf[:i + 1], self._buf[i + 1:]
        return line

    def read(self, n):
        while len(self._buf) < n:
            if not self._fill():
                break
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


def _parse_headers(header_lines):
    out = []
    for h in header_lines:
        if b":" in h:
            k, _, v = h.partition(b":")
            out.append((k.strip().decode("latin-1"), v.strip().decode("latin-1")))
    return out


def _header(headers, name):
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def _read_body(f, headers):
    te = (_header(headers, "transfer-encoding") or "").lower()
    cl = _header(headers, "content-length")
    if "chunked" in te:
        chunks = []
        while True:
            size_line = f.readline()
            if not size_line:
                break
            try:
                n = int(size_line.strip().split(b";")[0], 16)
            except ValueError:
                break
            if n == 0:
                f.readline()  # trailing CRLF
                break
            chunks.append(f.read(n))
            f.read(2)  # CRLF after chunk
        return b"".join(chunks)
    if cl:
        try:
            return f.read(int(cl))
        except (ValueError, OSError):
            return b""
    return b""


def inflate(headers, body: bytes) -> bytes:
    """Decompress gzip/deflate/br to raw bytes (full, untruncated). Returns body unchanged if not compressed."""
    enc = (_header(headers, "content-encoding") or "").lower()
    try:
        if "gzip" in enc:
            return gzip.decompress(body)
        if "deflate" in enc:
            return zlib.decompress(body)
        if "br" in enc:
            import brotli  # optional
            return brotli.decompress(body)
    except Exception:  # noqa: BLE001
        pass
    return body


def decode_body(headers, body: bytes) -> str:
    """Decompress gzip/deflate for display; returns text (best-effort)."""
    return inflate(headers, body).decode("utf-8", "replace")[:200000]


# ---------------------------------------------------------------- the proxy
class MitmProxy:
    """Threaded intercepting proxy. on_flow(flow) is called (from a worker thread) for each transaction;
    edit_response(flow) -> (status, headers, body) | None lets a caller rewrite a response before it is sent."""

    def __init__(self, ca: CertAuthority, on_flow=None, edit_response=None):
        self.ca = ca
        self.on_flow = on_flow          # optional UI notifier(flow); settable after construction
        self.edit_response = edit_response  # optional (flow)->(status,headers,body)|None for response interception
        self.intercept_request = None   # optional (req)->bool: edit req in place; return False to DROP the request
        self.flows: list = []           # full history (capped), so the panel has it even for early flows
        # Extension hooks shared by Workflows and Session handling (all default to no-ops so nothing changes
        # until a feature registers one). Each is a list of callbacks run in order on the proxy worker thread.
        self.request_rewriters: list = []   # fn(req: dict) -> None; mutate method/path/headers/body before forwarding
        self.response_rewriters: list = []  # fn(flow: dict) -> None; mutate status/resp_headers/resp_body after it returns
        self.response_observers: list = []  # fn(flow: dict) -> None; passive (e.g. detect a logged-out response)
        # WebSocket frame hooks (Burp/Caido-style). When either is set, WebSocket upgrades are parsed frame by
        # frame instead of blind-relayed, so frames can be viewed and edited.
        self.on_ws = None               # fn(frame: dict) for each WebSocket frame seen (live + history)
        self.edit_ws = None             # fn(frame: dict) -> bytes|None|False : new payload / unchanged / drop
        self.ws_flows: list = []        # WebSocket frame history (capped)
        self.http2 = False              # when True, offer HTTP/2 (h2) over ALPN and parse it (experimental)
        self._pool: dict = {}           # upstream keep-alive pool: (scheme,host,port) -> [idle http.client conns]
        self._pool_lock = threading.Lock()
        self._srv = None
        self.port = 0
        self._stop = False

    def start(self, port: int = 0) -> int:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(128)
        self._srv = srv
        self.port = srv.getsockname()[1]
        threading.Thread(target=self._accept_loop, daemon=True).start()
        return self.port

    def stop(self):
        self._stop = True
        try:
            if self._srv:
                self._srv.close()
        except OSError:
            pass

    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            head = _read_head_raw(conn)  # do NOT over-read: the TLS ClientHello may follow a CONNECT
            if not head:
                return
            first, header_lines, leftover = head
            parts = first.split(b" ")
            if len(parts) < 2:
                return
            method = parts[0].decode("latin-1")
            if method == "CONNECT":
                hostport = parts[1].decode("latin-1")
                host = hostport.rsplit(":", 1)[0]
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                try:
                    tls = self.ca.context_for(host, self.http2).wrap_socket(conn, server_side=True)
                except (ssl.SSLError, OSError):
                    return
                if self.http2 and tls.selected_alpn_protocol() == "h2":
                    self._serve_h2(tls, host)
                else:
                    self._serve_tls(tls, host)
            else:
                self._serve_plain(conn, first, header_lines, leftover)
        except Exception:  # noqa: BLE001 - never let one connection crash the proxy
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _serve_tls(self, tls, host):
        f = tls.makefile("rb")
        while not self._stop:
            head = _recv_headers(f)
            if not head:
                break
            first, header_lines = head
            parts = first.split(b" ")
            if len(parts) < 2:
                break
            method, path = parts[0].decode("latin-1"), parts[1].decode("latin-1")
            headers = _parse_headers(header_lines)
            # a WebSocket upgrade. If a WebSocket hook is registered (the panel is open), parse the connection
            # frame by frame so frames can be viewed/edited; otherwise blind-relay it (no overhead).
            if (_header(headers, "upgrade") or "").lower() == "websocket":
                raw = first + b"\r\n" + b"\r\n".join(header_lines) + b"\r\n\r\n"
                if self.on_ws is not None or self.edit_ws is not None:
                    self._ws_relay(tls, host, 443, path, raw)
                else:
                    self._blind_relay(tls, host, 443, raw)
                return
            body = _read_body(f, headers)
            if not self._transaction("https", host, 443, method, path, headers, body, tls):
                break

    def _serve_h2(self, tls, host):
        """Serve an HTTP/2 (h2) connection: parse each stream, run it through the shared pipeline, respond in h2."""
        from . import http2
        try:
            http2.Http2Handler(tls, host, self._fetch, lambda: self._stop).run()
        except Exception:  # noqa: BLE001 - never let one connection crash the proxy
            pass

    def _serve_plain(self, conn, first, header_lines, leftover):
        parts = first.split(b" ")
        method, url = parts[0].decode("latin-1"), parts[1].decode("latin-1")
        from urllib.parse import urlsplit
        u = urlsplit(url)
        host, port = u.hostname or "", u.port or 80
        path = (u.path or "/") + (("?" + u.query) if u.query else "")
        headers = _parse_headers(header_lines)
        f = _Prebuffered(conn, leftover)
        body = _read_body(f, headers)
        self._transaction("http", host, port, method, path, headers, body, conn)

    def _pool_get(self, key):
        with self._pool_lock:
            lst = self._pool.get(key)
            return lst.pop() if lst else None

    def _pool_put(self, key, conn):
        with self._pool_lock:
            lst = self._pool.setdefault(key, [])
            lst.append(conn)
            while len(lst) > 6:   # cap idle connections per host
                try:
                    lst.pop(0).close()
                except OSError:
                    pass

    def _upstream_request(self, scheme, host, port, method, path, body, fwd):
        """Forward one request upstream, reusing a kept-alive connection when possible (a fresh TLS handshake per
        request is the main reason proxied browsing feels slow). Retries once if a pooled connection was stale."""
        import http.client
        key = (scheme, host, port)
        last_err = None
        for _ in range(2):
            conn = self._pool_get(key)
            fresh = conn is None
            if fresh:
                conn = (http.client.HTTPSConnection(host, port, timeout=30, context=_upstream_ctx())
                        if scheme == "https" else http.client.HTTPConnection(host, port, timeout=30))
            try:
                conn.request(method, path, body=body or None, headers=dict(fwd))
                resp = conn.getresponse()
                rbody = resp.read()
                rheaders = resp.getheaders()
                status, reason, ver = resp.status, resp.reason, resp.version
                if ver == 11 and "close" not in (resp.getheader("connection") or "").lower():
                    self._pool_put(key, conn)   # keep-alive: reuse for the next request to this host
                else:
                    conn.close()
                return status, reason, rheaders, rbody
            except Exception as e:  # noqa: BLE001
                last_err = e
                try:
                    conn.close()
                except OSError:
                    pass
                if fresh:   # a brand-new connection failing is a real error, not a stale-pool miss
                    raise
        raise last_err

    def _fetch(self, req: dict) -> dict:
        """Run the full pipeline for one request dict and return the (possibly edited) response. Shared by the
        HTTP/1.1 and HTTP/2 paths so both get request rewriting, interception, workflows, session handling and
        history. Returns {"dropped": True}, {"error": msg}, or {"flow", "status", "reason", "headers", "body"}."""
        import http.client
        started = time.time()
        # request rewriting (Workflows match/replace on requests, Session cookie/token injection)
        for rw in self.request_rewriters:
            try:
                rw(req)
            except Exception:  # noqa: BLE001
                pass
        # request interception (Burp/Caido-style): block until the user edits + forwards, or drops the request
        if self.intercept_request is not None:
            try:
                keep = self.intercept_request(req)
            except Exception:  # noqa: BLE001
                keep = True
            if keep is False:
                return {"dropped": True}
        scheme, host, port = req["scheme"], req["host"], req["port"]
        method, path, headers, body = req["method"], req["path"], req["headers"], req["body"]
        fwd = [(k, v) for k, v in headers if k.lower() not in ("proxy-connection", "connection")]
        try:
            status, reason, rheaders, rbody = self._upstream_request(scheme, host, port, method, path, body, fwd)
        except Exception as e:  # noqa: BLE001 - upstream failure
            return {"error": str(e)}
        flow = {"time": time.strftime("%H:%M:%S"), "ts": started, "method": method, "scheme": scheme, "host": host,
                "path": path, "url": f"{scheme}://{host}{path}", "status": status, "reason": reason,
                "req_headers": headers, "req_body": body, "resp_headers": rheaders, "resp_body": rbody,
                "ms": int((time.time() - started) * 1000)}
        # response rewriting (Workflows match/replace on responses): mutate the flow in place
        for rw in self.response_rewriters:
            try:
                rw(flow)
            except Exception:  # noqa: BLE001
                pass
        status, reason = flow["status"], flow.get("reason", reason)
        rheaders, rbody = flow["resp_headers"], flow["resp_body"]
        # response interception: let the caller rewrite status/headers/body (blocking hold → edit → forward)
        if self.edit_response is not None:
            try:
                edited = self.edit_response(flow)
                if edited is not None:
                    status, rheaders, rbody = edited
            except Exception:  # noqa: BLE001
                pass
        self.flows.append(flow)
        del self.flows[:-2000]
        for obs in self.response_observers:   # passive observers (Session logged-out detection)
            try:
                obs(flow)
            except Exception:  # noqa: BLE001
                pass
        if self.on_flow is not None:
            try:
                self.on_flow(flow)
            except Exception:  # noqa: BLE001
                pass
        return {"flow": flow, "status": status, "reason": reason, "headers": rheaders, "body": rbody}

    def _transaction(self, scheme, host, port, method, path, headers, body, out_sock) -> bool:
        """Forward one HTTP/1.1 request upstream, relay the response to out_sock, capture the flow. Keep-alive?"""
        req = {"scheme": scheme, "host": host, "port": port, "method": method, "path": path,
               "headers": list(headers), "body": body}
        res = self._fetch(req)
        if res.get("dropped"):
            msg = b"Wyrm proxy: request dropped"
            try:
                out_sock.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                                 % (len(msg), msg))
            except OSError:
                pass
            return False
        if res.get("error"):
            msg = f"Wyrm proxy: upstream error: {res['error']}".encode()
            try:
                out_sock.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                                 % (len(msg), msg))
            except OSError:
                pass
            return False
        status, reason, rheaders, rbody = res["status"], res["reason"], res["headers"], res["body"]
        # relay to the browser with clean framing (buffered body -> Content-Length, drop chunked)
        out = [f"HTTP/1.1 {status} {reason}\r\n".encode("latin-1")]
        for k, v in rheaders:
            if k.lower() in ("transfer-encoding", "connection"):
                continue
            if k.lower() == "content-length":
                continue
            out.append(f"{k}: {v}\r\n".encode("latin-1"))
        out.append(f"Content-Length: {len(rbody)}\r\n".encode("latin-1"))
        out.append(b"Connection: keep-alive\r\n\r\n")
        try:
            out_sock.sendall(b"".join(out))
            if method != "HEAD" and status not in (204, 304):
                out_sock.sendall(rbody)
        except OSError:
            return False
        return True

    def _blind_relay(self, client_sock, host, port, initial):
        """Pipe bytes both ways without inspecting (WebSocket upgrade over TLS)."""
        try:
            up = _upstream_ctx().wrap_socket(socket.create_connection((host, port), timeout=30),
                                                          server_hostname=host)
            up.sendall(initial)
        except OSError:
            return
        def pipe(a, b):
            try:
                while True:
                    d = a.recv(65536)
                    if not d:
                        break
                    b.sendall(d)
            except OSError:
                pass
            finally:
                for s in (a, b):
                    try:
                        s.close()
                    except OSError:
                        pass
        threading.Thread(target=pipe, args=(client_sock, up), daemon=True).start()
        pipe(up, client_sock)

    # ---------------------------------------------------------------- WebSocket (frame-level)
    def _record_ws(self, frame):
        self.ws_flows.append(frame)
        del self.ws_flows[:-4000]
        if self.on_ws is not None:
            try:
                self.on_ws(frame)
            except Exception:  # noqa: BLE001
                pass

    def _ws_relay(self, client_tls, host, port, path, raw_request):
        """Relay a WebSocket connection frame by frame so each frame can be shown and (optionally) edited."""
        from . import wsframe
        try:
            up = _upstream_ctx().wrap_socket(socket.create_connection((host, port), timeout=30),
                                             server_hostname=host)
            up.sendall(raw_request)
        except OSError:
            return
        head = _read_head_raw(up)   # the server's handshake response (don't swallow the first frames)
        if not head:
            return
        rline, rlines, leftover = head
        try:
            client_tls.sendall(rline + b"\r\n" + b"\r\n".join(rlines) + b"\r\n\r\n")
        except OSError:
            return
        parts = rline.split(b" ")
        if len(parts) < 2 or parts[1] != b"101":   # not an upgrade after all: fall back to a blind pipe
            try:
                if leftover:
                    client_tls.sendall(leftover)
            except OSError:
                return
            self._ws_blind(client_tls, up)
            return
        creader = wsframe.SockReader(client_tls)         # frames FROM the page (masked)
        sreader = wsframe.SockReader(up, leftover)        # frames FROM the server (unmasked)
        t = threading.Thread(target=self._ws_pump, args=("out", creader, up, host, path, True), daemon=True)
        t.start()
        self._ws_pump("in", sreader, client_tls, host, path, False)
        for s in (client_tls, up):
            try:
                s.close()
            except OSError:
                pass

    def _ws_pump(self, direction, reader, dest, host, path, mask_out):
        """Read frames from `reader`, show/edit them, re-encode and send to `dest`. direction: 'out'=page→server."""
        from . import wsframe
        while not self._stop:
            try:
                fr = wsframe.read_frame(reader)
            except OSError:
                break
            if not fr:
                break
            opname = wsframe.OPCODE.get(fr["opcode"], str(fr["opcode"]))
            frame = {"dir": direction, "opcode": fr["opcode"], "opname": opname, "fin": fr["fin"],
                     "payload": fr["payload"], "host": host, "path": path, "url": f"wss://{host}{path}",
                     "time": time.strftime("%H:%M:%S")}
            self._record_ws(frame)
            payload, drop = fr["payload"], False
            if self.edit_ws is not None:
                try:
                    dec = self.edit_ws(frame)
                    if dec is False:
                        drop = True
                    elif isinstance(dec, (bytes, bytearray)):
                        payload = bytes(dec)
                except Exception:  # noqa: BLE001
                    pass
            if not drop:
                try:
                    dest.sendall(wsframe.build_frame(fr["fin"], fr["opcode"], payload, mask_out))
                except OSError:
                    break
            if fr["opcode"] == 0x8:   # close
                break

    @staticmethod
    def _ws_blind(a, b):
        def pipe(x, y):
            try:
                while True:
                    d = x.recv(65536)
                    if not d:
                        break
                    y.sendall(d)
            except OSError:
                pass
            finally:
                for s in (x, y):
                    try:
                        s.close()
                    except OSError:
                        pass
        threading.Thread(target=pipe, args=(a, b), daemon=True).start()
        pipe(b, a)
