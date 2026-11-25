#------------------------------------------------------------------------------
# Wyrm — tests/test_repeater.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Repeater fixes: JSON bodies are pretty-printed, and a stale Content-Length never overrides the real body
length when a request is resent (so an edited/reformatted body is sent correctly)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_pretty_json_formats_and_leaves_non_json_alone():
    from wyrm.panels.tools import ToolsTab
    assert ToolsTab._pretty_json('{"a":1,"b":2}') == '{\n  "a": 1,\n  "b": 2\n}'
    assert ToolsTab._pretty_json("not json at all") == "not json at all"
    assert ToolsTab._pretty_json("") == ""
    assert ToolsTab._pretty_json('{bad json') == '{bad json'   # invalid JSON is left untouched


def test_send_request_drops_stale_content_length():
    """An edited body must be sent with its real length — requests recomputes it only if we don't pass a stale one."""
    from wyrm.security import tools
    captured = {}

    class FakeResp:
        status_code = 200
        reason = "OK"
        headers = {"content-type": "text/plain"}
        text = "ok"
        content = b"ok"

    def fake_request(method, url, headers, data, timeout, proxies, verify, allow_redirects):
        captured["headers"] = headers
        captured["data"] = data
        return FakeResp()

    orig = tools.requests.request
    tools.requests.request = fake_request
    try:
        tools.send_request("POST", "http://t.test/", "Content-Length: 999\nX-Keep: 1", '{"a":1}')
    finally:
        tools.requests.request = orig

    hdr_keys = {k.lower() for k in captured["headers"]}
    assert "content-length" not in hdr_keys, "stale Content-Length should be dropped"
    assert "x-keep" in hdr_keys, "other headers must be preserved"
    assert captured["data"] == b'{"a":1}'


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
