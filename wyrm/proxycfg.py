#------------------------------------------------------------------------------
# Wyrm — wyrm/proxycfg.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Upstream-proxy TLS verification setting, per engagement (B7).

With an upstream proxy (Burp/ZAP) Wyrm can accept TLS errors — normal for a testing proxy that re-signs
traffic, but it must never be silent and it shouldn't leak from a lab engagement into personal browsing. The
value is stored per engagement (``proxy/insecure_eng/<id>``); an engagement with no value of its own, and
personal browsing (id 0), use the global ``proxy/insecure``. Pure functions over a QSettings-like object.
"""
from __future__ import annotations

GLOBAL_KEY = "proxy/insecure"


def _key(eng_id) -> str:
    return f"proxy/insecure_eng/{int(eng_id)}"


def _bool(v) -> bool:
    return v is True or str(v).lower() in ("true", "1", "yes")


def insecure_setting(settings, eng_id=0) -> bool:
    """The stored choice for this engagement (falls back to the global value)."""
    if eng_id:
        v = settings.value(_key(eng_id), None)
        if v is not None:
            return _bool(v)
    return _bool(settings.value(GLOBAL_KEY, False))


def set_insecure(settings, eng_id, on: bool) -> None:
    settings.setValue(_key(eng_id) if eng_id else GLOBAL_KEY, bool(on))


def upstream_unverified(settings, eng_id=0) -> bool:
    """True when TLS certificates are NOT being verified right now: upstream proxy on + insecure chosen."""
    return _bool(settings.value("proxy/enabled", False)) and insecure_setting(settings, eng_id)


def startup_engagement(settings) -> int:
    """The engagement Wyrm will open with (Chromium's flags are fixed at startup)."""
    try:
        return int(settings.value("engagement", 0) or 0)
    except (TypeError, ValueError):
        return 0
