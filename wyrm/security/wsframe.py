#------------------------------------------------------------------------------
# Wyrm — wyrm/security/wsframe.py
# Developers: @kwan and @oda (intercepting HTTPS proxy — WebSocket frames)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Minimal RFC 6455 WebSocket frame codec, used by the intercepting proxy to view and edit frames.

read_frame(reader)                 -> {"fin", "opcode", "payload"} | None   (payload already unmasked)
build_frame(fin, opcode, payload, mask) -> bytes                             (masked when mask=True)

Client→server frames are masked, server→client frames are not (RFC 6455 §5), so when forwarding the proxy
re-encodes with the masking the destination requires.
"""
from __future__ import annotations

import os
import struct

OPCODE = {0x0: "continuation", 0x1: "text", 0x2: "binary", 0x8: "close", 0x9: "ping", 0xA: "pong"}


class SockReader:
    """Read exact byte counts from a socket, starting with any bytes already received."""

    def __init__(self, sock, initial: bytes = b""):
        self._sock = sock
        self._buf = bytearray(initial)

    def read_exact(self, n: int) -> "bytes | None":
        while len(self._buf) < n:
            try:
                d = self._sock.recv(65536)
            except OSError:
                return None
            if not d:
                return None
            self._buf += d
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


def read_frame(reader: SockReader) -> "dict | None":
    """Read one WebSocket frame. Returns {"fin", "opcode", "payload"} with the payload unmasked, or None at EOF."""
    hdr = reader.read_exact(2)
    if not hdr or len(hdr) < 2:
        return None
    b0, b1 = hdr[0], hdr[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    if length == 126:
        ext = reader.read_exact(2)
        if not ext:
            return None
        length = struct.unpack("!H", ext)[0]
    elif length == 127:
        ext = reader.read_exact(8)
        if not ext:
            return None
        length = struct.unpack("!Q", ext)[0]
    if length > 64 * 1024 * 1024:   # refuse absurd frames rather than allocate wildly
        return None
    mask = b""
    if masked:
        mask = reader.read_exact(4)
        if mask is None:
            return None
    payload = reader.read_exact(length) if length else b""
    if length and payload is None:
        return None
    if masked and payload:
        payload = bytes(payload[i] ^ mask[i & 3] for i in range(len(payload)))
    return {"fin": fin, "opcode": opcode, "payload": payload}


def build_frame(fin: bool, opcode: int, payload: bytes, mask: bool) -> bytes:
    """Encode one WebSocket frame (masked with a fresh random key when mask=True)."""
    payload = bytes(payload or b"")
    out = bytearray([(0x80 if fin else 0) | (opcode & 0x0F)])
    length = len(payload)
    mbit = 0x80 if mask else 0
    if length < 126:
        out.append(mbit | length)
    elif length < 65536:
        out.append(mbit | 126)
        out += struct.pack("!H", length)
    else:
        out.append(mbit | 127)
        out += struct.pack("!Q", length)
    if mask:
        key = os.urandom(4)
        out += key
        out += bytes(payload[i] ^ key[i & 3] for i in range(length))
    else:
        out += payload
    return bytes(out)
