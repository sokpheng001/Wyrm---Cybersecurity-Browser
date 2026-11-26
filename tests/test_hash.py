#------------------------------------------------------------------------------
# Wyrm — tests/test_hash.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Hash tool: multi-algorithm digests, HMAC, and the weak-password hint."""
import hashlib
import hmac

from wyrm.security import payloads as p
from wyrm.security import tools as t

WORDS = p.LISTS["Common passwords"] + p.LISTS["Common usernames"]


def test_compute_hashes_covers_algorithms_and_crc():
    h = t.compute_hashes("abc")
    assert h["md5"] == hashlib.md5(b"abc").hexdigest()
    assert h["sha256"] == hashlib.sha256(b"abc").hexdigest()
    for n in ("sha224", "sha384", "sha512", "sha3_256", "blake2b"):
        assert n in h
    assert h["crc32"] == "352441c2"      # known CRC-32 of "abc"


def test_hmac_matches_stdlib_and_empty_key_noop():
    hm = t.hmac_hashes("data", "key")
    assert hm["hmac-sha256"] == hmac.new(b"key", b"data", "sha256").hexdigest()
    assert t.hmac_hashes("data", "") == {}


def test_crack_hint_flags_common_passwords():
    assert t.crack_hint(hashlib.md5(b"password").hexdigest(), WORDS) == ("password", "md5")
    assert t.crack_hint(hashlib.sha1(b"admin").hexdigest(), WORDS) == ("admin", "sha1")
    assert t.crack_hint(hashlib.sha256(b"root").hexdigest(), WORDS) == ("root", "sha256")


def test_crack_hint_returns_none_for_unknown_or_nonhex():
    assert t.crack_hint(hashlib.md5(b"not-in-any-list-xyz").hexdigest(), WORDS) is None
    assert t.crack_hint("deadbeef", WORDS) is None       # not a known digest length
    assert t.crack_hint("zz" * 16, WORDS) is None        # right length, not hex
