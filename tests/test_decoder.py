#------------------------------------------------------------------------------
# Wyrm — tests/test_decoder.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Decoder transforms, including the new URL-safe Base64, JWT, and gzip/deflate decompress ones."""
import base64
import gzip
import json
import zlib

from wyrm.security import tools as t


def test_urlsafe_base64_roundtrip_no_padding():
    enc = t.transform("Base64 URL-safe encode", "hi>there?&x")
    assert "=" not in enc and "+" not in enc and "/" not in enc
    assert t.transform("Base64 decode", enc) == "hi>there?&x"


def test_gzip_decompress():
    blob = base64.b64encode(gzip.compress(b"hello world")).decode()
    assert t.transform("Gzip decompress (base64 in)", blob) == "hello world"


def test_zlib_and_raw_deflate_decompress():
    assert t.transform("Zlib/Deflate decompress (base64 in)",
                       base64.b64encode(zlib.compress(b"abc")).decode()) == "abc"
    co = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    raw = co.compress(b"raw deflate") + co.flush()
    assert t.transform("Zlib/Deflate decompress (base64 in)",
                       base64.b64encode(raw).decode()) == "raw deflate"


def test_jwt_decode_shows_claims_and_alg_none_warning():
    def seg(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    tok = seg({"alg": "none", "typ": "JWT"}) + "." + seg({"sub": "1", "role": "admin"}) + "."
    out = t.transform("JWT decode", tok)
    assert '"role": "admin"' in out and '"alg": "none"' in out
    assert "signatures aren't checked" in out


def test_binary_output_falls_back_to_hex():
    blob = base64.b64encode(gzip.compress(b"\xff\xfe\x00")).decode()
    assert t.transform("Gzip decompress (base64 in)", blob).startswith("hex: ")


def test_bad_input_never_raises():
    for name in ("Gzip decompress (base64 in)", "Zlib/Deflate decompress (base64 in)",
                 "JWT decode", "Base64 decode"):
        for bad in ("", "@@@@", "not base64 !!", "short"):
            assert isinstance(t.transform(name, bad), str)   # returns a string (maybe "[error] …"), no exception
    assert t.transform("JWT decode", "notajwt").startswith("[error]")
