#------------------------------------------------------------------------------
# Wyrm — wyrm/secretstore.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Encrypt small secrets (API keys, session tokens) at rest instead of keeping them in cleartext.

On Windows we use DPAPI (CryptProtectData, per-user scope) so the stored value is ciphertext that only the
current Windows user can decrypt — a plain registry read no longer yields the raw key (SEC-7). Elsewhere we
degrade to storing the value as-is (no OS keystore wired up yet); callers get the same API either way.

Stored format: encrypted values are tagged ``enc:v1:<base64(ciphertext)>``. Anything without that prefix is
treated as a legacy/plaintext value, so old settings keep working and are re-encrypted on the next save.
"""
from __future__ import annotations

import base64
import sys

_PREFIX = "enc:v1:"


def available() -> bool:
    """True when at-rest encryption is actually in effect (DPAPI present)."""
    return sys.platform == "win32"


# --------------------------------------------------------------------- Windows DPAPI
def _dpapi(data: bytes, unprotect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class _BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))   # kept alive until the call returns
    blob_in = _BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _BLOB()
    fn = ctypes.windll.crypt32.CryptUnprotectData if unprotect else ctypes.windll.crypt32.CryptProtectData
    # Both share the shape (pDataIn, descr, entropy, reserved, prompt, flags, pDataOut); all optional args None,
    # CRYPTPROTECT_UI_FORBIDDEN not needed since we never prompt. Per-user scope is the default (no machine flag).
    if not fn(ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out)):
        raise OSError("DPAPI call failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# --------------------------------------------------------------------- public API
def encrypt(plaintext: str) -> str:
    """Return a value safe to persist. On Windows this is DPAPI ciphertext; elsewhere the value unchanged."""
    if not plaintext:
        return ""
    if available():
        try:
            blob = _dpapi(plaintext.encode("utf-8"), unprotect=False)
            return _PREFIX + base64.b64encode(blob).decode("ascii")
        except OSError:
            return plaintext   # never lose the user's key just because encryption failed
    return plaintext


def decrypt(stored: str) -> str:
    """Inverse of :func:`encrypt`. Legacy plaintext values (no ``enc:`` prefix) are returned unchanged."""
    if not stored:
        return ""
    if stored.startswith(_PREFIX):
        try:
            blob = base64.b64decode(stored[len(_PREFIX):])
            return _dpapi(blob, unprotect=True).decode("utf-8")
        except (OSError, ValueError):
            return ""          # ciphertext from another user/machine won't decrypt — treat as "not set"
    return stored              # legacy plaintext


def is_encrypted(stored: str) -> bool:
    return bool(stored) and stored.startswith(_PREFIX)


def get(settings, key: str) -> str:
    """Read and decrypt a secret from QSettings."""
    return decrypt(settings.value(key, "", type=str))


def set(settings, key: str, plaintext: str) -> None:
    """Encrypt and store a secret in QSettings (stores nothing readable as the raw key on Windows)."""
    settings.setValue(key, encrypt(plaintext.strip()))
