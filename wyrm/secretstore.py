#------------------------------------------------------------------------------
# Wyrm — wyrm/secretstore.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Keep small secrets (API keys, session tokens) out of cleartext settings files.

F4 (v0.5.0 build hardening): named secrets such as the AI Triage API key live in the OS keyring via the
`keyring` package — macOS Keychain, Windows Credential Manager, Linux Secret Service — under service "Wyrm".
A value still found in QSettings (older builds kept it in ~/Library/Preferences/com.hackpi.Wyrm.plist in plain
text on macOS/Linux) is moved into the keyring on startup and deleted from QSettings. If no keyring backend is
available the secret is kept in memory for this session only — never written to disk in plain text — and the
Settings page shows a warning (see :func:`keyring_status`).

Byte blobs (e.g. the MITM CA key) still use the helpers below. On Windows we use DPAPI (CryptProtectData, per-user scope) so the stored value is ciphertext that only the
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


_MAGIC = b"WYRMDPAPI1\n"   # marks a DPAPI-protected byte blob on disk (e.g. the MITM CA private key)


def protect_bytes(data: bytes) -> bytes:
    """Return bytes safe to write to disk: DPAPI blob (magic-tagged) on Windows, else the data unchanged."""
    if data and available():
        try:
            return _MAGIC + _dpapi(data, unprotect=False)
        except OSError:
            return data
    return data


def unprotect_bytes(blob: bytes) -> bytes:
    """Inverse of :func:`protect_bytes`. Un-tagged (legacy/plain) data is returned unchanged."""
    if blob.startswith(_MAGIC):
        return _dpapi(blob[len(_MAGIC):], unprotect=True)
    return blob


def is_protected_bytes(blob: bytes) -> bool:
    return blob.startswith(_MAGIC)


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


# --------------------------------------------------------------------- OS keyring (F4)
SERVICE = "Wyrm"
# QSettings key -> keyring username. Only these secrets go to the keyring; anything else keeps the old path.
KEYRING_ACCOUNTS = {"ai/api_key": "ai_api_key"}
_session: dict[str, str] = {}   # fallback when no keyring backend exists: memory only, never disk
_backend_override = None        # tests inject a backend here


def _keyring():
    """The usable keyring module/backend, or None (no package, or only the 'fail'/null backend)."""
    if _backend_override is not None:
        return _backend_override
    try:
        import keyring
        from keyring.backends import fail
        kr = keyring.get_keyring()
        if isinstance(kr, fail.Keyring) or getattr(kr, "priority", 0) <= 0:
            return None
        return keyring
    except Exception:  # noqa: BLE001 — import errors, broken D-Bus, locked keychain probe, …
        return None


def keyring_status() -> tuple[bool, str]:
    """(usable, human description) for the Settings page."""
    kr = _keyring()
    if kr is None:
        return False, ("No secure key store is available on this system (macOS Keychain / Windows Credential "
                       "Manager / Secret Service). Your key will be kept only until Wyrm quits.")
    try:
        name = type(kr.get_keyring()).__module__.rsplit(".", 1)[-1] if hasattr(kr, "get_keyring") else "keyring"
    except Exception:  # noqa: BLE001
        name = "keyring"
    return True, {"macOS": "Stored in the macOS Keychain", "Windows": "Stored in Windows Credential Manager",
                  "SecretService": "Stored in the Secret Service keyring",
                  "kwallet": "Stored in KWallet"}.get(name, "Stored in the system keyring")


def _remove_setting(settings, key: str) -> None:
    try:
        settings.remove(key)
    except Exception:  # noqa: BLE001
        pass


def migrate(settings) -> list[str]:
    """Move any keyring-managed secret still in QSettings into the keyring and delete it from QSettings.
    Returns the keys that were moved. Safe to call every startup."""
    moved = []
    kr = _keyring()
    for key, account in KEYRING_ACCOUNTS.items():
        stored = settings.value(key, "", type=str)
        if not stored:
            continue
        plain = decrypt(stored)
        if kr is None:
            # Can't move it anywhere safe: keep it for this session, but stop leaving it on disk in plain text.
            if plain:
                _session[key] = plain
            if not is_encrypted(stored):
                _remove_setting(settings, key)
            continue
        try:
            if plain:
                kr.set_password(SERVICE, account, plain)
            _remove_setting(settings, key)
            moved.append(key)
        except Exception:  # noqa: BLE001 — leave it where it is rather than lose the user's key
            pass
    return moved


def get(settings, key: str) -> str:
    """Read a secret: OS keyring for keyring-managed keys (migrating any leftover QSettings copy first), else
    decrypt from QSettings."""
    account = KEYRING_ACCOUNTS.get(key)
    if account is None:
        return decrypt(settings.value(key, "", type=str))
    if settings.value(key, "", type=str):
        migrate(settings)
    kr = _keyring()
    if kr is None:
        return _session.get(key, "")
    try:
        return kr.get_password(SERVICE, account) or ""
    except Exception:  # noqa: BLE001
        return _session.get(key, "")


def set(settings, key: str, plaintext: str) -> None:
    """Store a secret. Keyring-managed keys go to the OS keyring (an empty value deletes it) and never touch
    QSettings; with no keyring backend they are held in memory for this session only."""
    plaintext = (plaintext or "").strip()
    account = KEYRING_ACCOUNTS.get(key)
    if account is None:
        settings.setValue(key, encrypt(plaintext))
        return
    _remove_setting(settings, key)
    kr = _keyring()
    if kr is None:
        if plaintext:
            _session[key] = plaintext
        else:
            _session.pop(key, None)
        return
    if plaintext:
        kr.set_password(SERVICE, account, plaintext)
        _session.pop(key, None)
    else:
        try:
            kr.delete_password(SERVICE, account)
        except Exception:  # noqa: BLE001 — nothing stored
            pass
        _session.pop(key, None)
