#------------------------------------------------------------------------------
# Wyrm — tests/test_proxycfg.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""B7: upstream TLS verification is chosen per engagement and reported, never silently global."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wyrm import proxycfg  # noqa: E402


class S:
    def __init__(self, **kv):
        self.d = dict(kv)

    def value(self, k, default=None, type=None):  # noqa: A002
        return self.d.get(k, default)

    def setValue(self, k, v):  # noqa: N802
        self.d[k] = v


def test_off_without_upstream_proxy():
    s = S(**{"proxy/insecure": True})
    assert proxycfg.upstream_unverified(s, 0) is False


def test_per_engagement_overrides_global():
    s = S(**{"proxy/enabled": True, "proxy/insecure": True})
    assert proxycfg.upstream_unverified(s, 0) is True           # personal: global value
    proxycfg.set_insecure(s, 7, False)                           # lab engagement 7 verifies
    assert proxycfg.upstream_unverified(s, 7) is False
    assert proxycfg.upstream_unverified(s, 3) is True            # an engagement without its own value: global
    proxycfg.set_insecure(s, 0, False)
    proxycfg.set_insecure(s, 3, True)
    assert proxycfg.upstream_unverified(s, 0) is False and proxycfg.upstream_unverified(s, 3) is True


def test_qsettings_string_values():
    s = S(**{"proxy/enabled": "true", "proxy/insecure_eng/2": "false", "proxy/insecure": "true", "engagement": "2"})
    assert proxycfg.startup_engagement(s) == 2
    assert proxycfg.upstream_unverified(s, proxycfg.startup_engagement(s)) is False
