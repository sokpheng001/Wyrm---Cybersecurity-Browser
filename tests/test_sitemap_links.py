#------------------------------------------------------------------------------
# Wyrm — tests/test_sitemap_links.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""QA-L5: the Site map keeps only same-origin page links."""
from wyrm.panels.sitemap import same_origin_links


def test_keeps_same_origin_and_resolves_relative():
    out = same_origin_links("https://a.test/x/page", ["/admin", "next", "https://a.test/y#top", "#frag"])
    assert out == ["https://a.test/admin", "https://a.test/x/next", "https://a.test/y"]


def test_drops_other_origins_and_schemes():
    hrefs = ["https://b.test/", "http://a.test/", "https://a.test:8443/", "javascript:alert(1)",
             "mailto:x@a.test", "data:text/html,hi", "", None, 5]
    assert same_origin_links("https://a.test/", hrefs) == []


def test_dedupes_and_ignores_non_http_page():
    assert same_origin_links("https://a.test/", ["/a", "/a", "/a#b"]) == ["https://a.test/a"]
    assert same_origin_links("about:blank", ["/a"]) == []
