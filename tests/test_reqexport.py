#------------------------------------------------------------------------------
# Wyrm — tests/test_reqexport.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Export one request to cURL / Python / fetch / PowerShell, and parse a raw HTTP request."""
import json

import pytest

from wyrm.security import reqexport

REQ = {"method": "POST", "url": "https://api.test/login",
       "headers": {"Content-Type": "application/json", "X-Api": "k", "Content-Length": "13", "Host": "api.test"},
       "body": '{"u":"a\'b"}'}


def test_parse_raw_builds_url_from_host():
    req = reqexport.parse_raw("POST /login HTTP/1.1\nHost: api.test\nX-Api: k\n\n{\"u\":1}")
    assert req["method"] == "POST"
    assert req["url"] == "https://api.test/login"
    assert req["headers"]["X-Api"] == "k"
    assert req["body"] == '{"u":1}'


def test_parse_raw_absolute_url_wins_and_crlf_ok():
    req = reqexport.parse_raw("GET https://x.test/a?b=1 HTTP/1.1\r\nHost: ignored\r\n\r\n")
    assert req["url"] == "https://x.test/a?b=1"


def test_parse_raw_needs_a_request_line():
    with pytest.raises(ValueError):
        reqexport.parse_raw("garbage")


def test_curl_and_skip_computed_headers():
    out = reqexport.to_code(REQ, "cURL")
    assert out.startswith("curl -i -X POST")
    assert "'X-Api: k'" in out
    assert "Content-Length" not in out and "Host:" not in out   # client-computed headers are dropped


def test_python_is_valid_and_quotes_body():
    out = reqexport.to_code(REQ, "Python (requests)")
    assert "import requests" in out
    assert json.dumps(REQ["body"]) in out    # body is a proper Python string literal (quote inside is escaped)
    compile(out, "<gen>", "exec")            # generated Python at least parses


def test_fetch_includes_body_only_for_methods_that_take_one():
    assert "body:" in reqexport.to_code(REQ, "JavaScript (fetch)")
    get = {**REQ, "method": "GET", "body": ""}
    assert "body:" not in reqexport.to_code(get, "JavaScript (fetch)")


def test_powershell_escapes_quotes_and_splits_content_type():
    out = reqexport.to_code(REQ, "PowerShell")
    assert "-ContentType 'application/json'" in out
    assert "''" in out          # the single quote in the body is doubled, not left raw
    assert "Invoke-WebRequest" in out


def test_unknown_language_raises():
    with pytest.raises(ValueError):
        reqexport.to_code(REQ, "COBOL")
