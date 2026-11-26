#------------------------------------------------------------------------------
# Wyrm — tests/test_suggest.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Tool auto-suggestions from page info + analysis result."""
from wyrm.security import suggest


def test_login_page_suggests_auth_and_intruder():
    page = {"forms": [{"method": "post", "password": True, "csrf": True, "action": "/login"}]}
    tools = {t["tool"] for t in suggest.suggest_tools(page, {})}
    assert "Session / auth" in tools and "Intruder" in tools


def test_csrfless_password_form_suggests_scanner():
    page = {"forms": [{"method": "post", "password": True, "csrf": False}]}
    tips = suggest.suggest_tools(page, {})
    assert any(t["tool"] == "Scanner" and "CSRF" in t["reason"] for t in tips)


def test_js_endpoints_suggest_js_recon_and_sitemap():
    result = {"issues": [{"category": "JavaScript: endpoints"}]}
    tips = suggest.suggest_tools({}, result)
    assert any(t["tool"] == "Scanner" and t["sub"] == "JS recon" for t in tips)
    assert any(t["tool"] == "Site map" for t in tips)


def test_post_form_suggests_repeater_as_a_tools_subtool():
    tips = suggest.suggest_tools({"forms": [{"method": "post"}]}, {})
    rep = [t for t in tips if t["sub"] == "Repeater"]
    assert rep and rep[0]["tool"] == "Tools"   # Repeater lives inside the Tools tab


def test_ranking_priority_and_limit_and_dedup():
    page = {"forms": [{"method": "post", "password": True, "csrf": False}],
            "scripts": ["a", "b", "c", "d", "e"], "iframes": 2}
    result = {"issues": [{"category": "CORS"}, {"category": "Cookies"},
                         {"category": "JavaScript: possible secrets"}]}
    tips = suggest.suggest_tools(page, result, limit=6)
    assert len(tips) <= 6
    assert [t["priority"] for t in tips] == sorted(t["priority"] for t in tips)   # ranked
    keys = [(t["tool"], t["sub"]) for t in tips]
    assert len(keys) == len(set(keys))                                            # de-duplicated


def test_blank_page_still_offers_baseline():
    assert {t["tool"] for t in suggest.suggest_tools({}, {})} == {"Traffic", "Proxy"}
