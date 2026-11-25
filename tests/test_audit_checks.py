#------------------------------------------------------------------------------
# Wyrm — tests/test_audit_checks.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Tests for the active-scanner checks (wyrm/security/audit/checks.py).

Focus: the new blind/time-based SQL injection check. A fake `send` sleeps for the number of seconds embedded in
a SLEEP()/pg_sleep()/WAITFOR payload, so the check's timing oracle is exercised with small, fast durations.
Run: `python -m pytest tests/test_audit_checks.py` (or run this file directly)."""
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wyrm.security.audit import checks as chk  # noqa: E402

_SLEEP = re.compile(r"(?:SLEEP|pg_sleep)\((\d+(?:\.\d+)?)\)|WAITFOR DELAY '0:0:(\d+(?:\.\d+)?)'", re.I)


def _point():
    return {"loc": "query", "name": "id", "value": "1"}


def _build(payload):
    # the real builders url-encode; for a unit test we keep the payload readable so the fake DB can see the sleep
    return ("http://target/items?id=" + payload, {}, None)


def _make_send(sleeps=True, fixed_delay=0.0):
    def send(url, headers, body):
        if fixed_delay:
            time.sleep(fixed_delay)                 # a naturally slow endpoint (no injection)
        elif sleeps:
            m = _SLEEP.search(url)
            if m:
                time.sleep(float(m.group(1) or m.group(2)))   # DB executed our sleep
        return {"status": 200, "headers": {}, "text": "ok", "location": "", "url": url}
    return send


FAST = (0.4, 0.8)   # keep the test quick while preserving the 1x/2x relationship


def test_blind_sqli_detected_when_time_scales():
    c = chk.SqlBlindTime(time_based=True, probe_secs=FAST)
    f = c.run(_point(), _build, _make_send(sleeps=True), baseline=None, rand="abc")
    assert f is not None, "a sleepable parameter should be flagged"
    assert f["check"] == "sqli" and f["severity"] == "high"
    assert f["confidence"] == "firm"


def test_no_finding_when_endpoint_ignores_sleep():
    c = chk.SqlBlindTime(time_based=True, probe_secs=FAST)
    f = c.run(_point(), _build, _make_send(sleeps=False), baseline=None, rand="abc")
    assert f is None


def test_no_false_positive_on_naturally_slow_endpoint():
    # every response is slow (>= n1*0.9) but not injectable — the baseline guard must suppress the finding
    c = chk.SqlBlindTime(time_based=True, probe_secs=FAST)
    f = c.run(_point(), _build, _make_send(sleeps=False, fixed_delay=0.5), baseline=None, rand="abc")
    assert f is None


def test_time_based_off_skips_the_check():
    c = chk.SqlBlindTime(time_based=False, probe_secs=FAST)
    f = c.run(_point(), _build, _make_send(sleeps=True), baseline=None, rand="abc")
    assert f is None


def test_blind_sqli_is_in_the_standard_thorough_set_only():
    names = [type(c).__name__ for c in chk.standard(time_based=True)]
    assert "SqlBlindTime" in names
    fast = chk.standard(time_based=False)
    # present in Fast too, but inert (its run() returns None when time_based is off)
    sb = [c for c in fast if type(c).__name__ == "SqlBlindTime"]
    assert sb and sb[0].time_based is False


def _bool_send(injectable=True):
    """Fake endpoint: a boolean-injectable query returns the full list for a TRUE/original request and an empty
    page for a FALSE one. A non-injectable endpoint always returns the same page."""
    rows = "".join(f"<tr><td>{i}</td><td>product-{i}</td><td>$9.{i:02d}</td></tr>" for i in range(40))
    full = {"status": 200, "text": f"<table>{rows}</table>", "headers": {}, "location": "", "url": "http://t/"}
    empty = {"status": 200, "text": "<table></table><p>No products matched.</p>", "headers": {},
             "location": "", "url": "http://t/"}

    def send(url, headers, body):
        if not injectable:
            return dict(full)
        if re.search(r"1'='2|1=2|'1'='2", url):   # FALSE condition
            return dict(empty)
        return dict(full)                          # original or TRUE condition
    return send


def test_boolean_blind_sqli_detected():
    c = chk.SqlBlindBoolean()
    send = _bool_send(injectable=True)
    baseline = send("http://target/items?id=1", {}, None)   # the original (TRUE-like) page
    f = c.run(_point(), _build, send, baseline=baseline, rand="abc")
    assert f is not None and f["check"] == "sqli" and f["severity"] == "high"
    assert "boolean" in f["title"].lower()


def test_boolean_blind_sqli_no_false_positive_on_static_page():
    c = chk.SqlBlindBoolean()
    send = _bool_send(injectable=False)
    baseline = send("http://target/items?id=1", {}, None)
    f = c.run(_point(), _build, send, baseline=baseline, rand="abc")
    assert f is None


def _cors_send(acao_mode):
    """Fake endpoint whose ACAO behaviour depends on the request Origin header."""
    def send(url, headers, body):
        origin = headers.get("Origin", "")
        H = {}
        if acao_mode == "reflect":
            H["access-control-allow-origin"] = origin
        elif acao_mode == "reflect-creds":
            H["access-control-allow-origin"] = origin
            H["access-control-allow-credentials"] = "true"
        elif acao_mode == "null":
            H["access-control-allow-origin"] = "null"
        elif acao_mode == "same-origin":
            H["access-control-allow-origin"] = "https://trusted.example"
        return {"status": 200, "headers": H, "text": "{}", "location": "", "url": url}
    return send


def test_cors_reflected_origin_with_credentials_is_high():
    c = chk.CorsMisconfig()
    f = c.run_request("GET", "https://api.test/me", {}, "", _cors_send("reflect-creds"), baseline=None, rand="abc")
    assert f is not None and f["check"] == "cors" and f["severity"] == "high"
    assert "credential" in f["evidence"].lower()


def test_cors_reflected_origin_without_credentials_is_medium():
    c = chk.CorsMisconfig()
    f = c.run_request("GET", "https://api.test/data", {}, "", _cors_send("reflect"), baseline=None, rand="abc")
    assert f is not None and f["severity"] == "medium"


def test_cors_null_origin_flagged():
    c = chk.CorsMisconfig()
    f = c.run_request("GET", "https://api.test/x", {}, "", _cors_send("null"), baseline=None, rand="abc")
    assert f is not None and "null" in f["evidence"].lower()


def test_cors_fixed_allowlist_is_clean():
    c = chk.CorsMisconfig()
    f = c.run_request("GET", "https://api.test/x", {}, "", _cors_send("same-origin"), baseline=None, rand="abc")
    assert f is None


_XML_BODY = '<?xml version="1.0"?><order><item>widget</item><qty>2</qty></order>'


def _xxe_send(vulnerable=True):
    def send(url, headers, body):
        text = "<result>ok</result>"
        if vulnerable and body and "file:///etc/passwd" in body and "&xxe;" in body:
            # a vulnerable parser resolves the entity and reflects the file content
            text = "<result>root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:</result>"
        return {"status": 200, "headers": {"content-type": "application/xml"}, "text": text,
                "location": "", "url": url}
    return send


def test_xxe_file_disclosure_detected():
    c = chk.Xxe()
    f = c.run_request("POST", "https://api.test/orders", {"Content-Type": "application/xml"}, _XML_BODY,
                      _xxe_send(vulnerable=True), baseline=None, rand="abc")
    assert f is not None and f["check"] == "xxe" and f["severity"] == "high"
    assert "entity" in f["evidence"].lower()


def test_xxe_safe_parser_no_finding():
    c = chk.Xxe()
    f = c.run_request("POST", "https://api.test/orders", {"Content-Type": "application/xml"}, _XML_BODY,
                      _xxe_send(vulnerable=False), baseline=None, rand="abc")
    assert f is None


def test_xxe_skips_non_xml_requests():
    c = chk.Xxe()
    f = c.run_request("POST", "https://api.test/orders", {"Content-Type": "application/json"},
                      '{"item":"widget"}', _xxe_send(vulnerable=True), baseline=None, rand="abc")
    assert f is None


def test_xxe_payload_references_entity_in_first_text_node():
    # the builder must both define the entity (DOCTYPE) and reference it, or the probe proves nothing
    out = chk._xml_with_entity(_XML_BODY, '<!ENTITY xxe SYSTEM "file:///etc/passwd">', "&xxe;")
    assert out is not None
    assert "<!DOCTYPE" in out and "file:///etc/passwd" in out
    assert "&xxe;" in out and "<item>&xxe;</item>" in out


def _host_send(mode):
    def send(url, headers, body):
        xfh = headers.get("X-Forwarded-Host") or headers.get("X-Host") or headers.get("Host") or ""
        H, text, status = {}, "<html>home</html>", 200
        if mode == "redirect" and xfh and "attacker.example" in xfh:
            H["location"] = f"https://{xfh}/login"; status = 302
        elif mode == "reflect" and xfh and "attacker.example" in xfh:
            text = f'<link rel="canonical" href="https://{xfh}/"><a href="https://{xfh}/reset">reset</a>'
        return {"status": status, "headers": H, "text": text, "location": H.get("location", ""), "url": url}
    return send


def test_host_header_poisoned_redirect_is_high():
    c = chk.HostHeaderInjection()
    f = c.run_request("GET", "https://app.test/login", {"Host": "app.test"}, "",
                      _host_send("redirect"), baseline=None, rand="abc")
    assert f is not None and f["check"] == "host-header" and f["severity"] == "high"


def test_host_header_reflected_in_body_is_medium():
    c = chk.HostHeaderInjection()
    f = c.run_request("GET", "https://app.test/", {"Host": "app.test"}, "",
                      _host_send("reflect"), baseline=None, rand="abc")
    assert f is not None and f["severity"] == "medium"


def test_host_header_clean_app_no_finding():
    c = chk.HostHeaderInjection()
    f = c.run_request("GET", "https://app.test/", {"Host": "app.test"}, "",
                      _host_send("clean"), baseline=None, rand="abc")
    assert f is None


def _gql_send(enabled=True):
    def send(url, headers, body):
        if enabled and body and "__schema" in body:
            return {"status": 200, "headers": {"content-type": "application/json"},
                    "text": '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"name":"User","kind":"OBJECT"}]}}}',
                    "location": "", "url": url}
        return {"status": 200, "headers": {}, "text": '{"errors":[{"message":"introspection disabled"}]}',
                "location": "", "url": url}
    return send


def test_graphql_introspection_enabled_detected():
    c = chk.GraphqlIntrospection()
    f = c.run_request("POST", "https://api.test/graphql", {}, '{"query":"{me{id}}"}',
                      _gql_send(enabled=True), baseline=None, rand="abc")
    assert f is not None and f["check"] == "graphql-introspection"


def test_graphql_introspection_disabled_no_finding():
    c = chk.GraphqlIntrospection()
    f = c.run_request("POST", "https://api.test/graphql", {}, '{"query":"{me{id}}"}',
                      _gql_send(enabled=False), baseline=None, rand="abc")
    assert f is None


def test_graphql_check_skips_get_and_non_graphql():
    c = chk.GraphqlIntrospection()
    assert c.run_request("GET", "https://api.test/graphql", {}, "", _gql_send(True), None, "abc") is None
    assert c.run_request("POST", "https://api.test/users", {}, '{"name":"x"}', _gql_send(True), None, "abc") is None


def test_insertion_points_include_dynamic_path_segments():
    from wyrm.security.audit.points import insertion_points
    pts = insertion_points("GET", "https://t.test/api/users/123/report.pdf?x=1", {}, "")
    path_vals = [m["value"] for m, b in pts if m["loc"] == "path"]
    assert "123" in path_vals            # numeric id
    assert "report.pdf" in path_vals     # filename (dot) / last segment
    assert "api" not in path_vals        # static segments aren't fuzzed
    assert "users" not in path_vals


def test_path_builder_preserves_traversal_slashes():
    from wyrm.security.audit.points import insertion_points
    pts = insertion_points("GET", "https://t.test/files/123", {}, "")
    build = next(b for m, b in pts if m["loc"] == "path" and m["value"] == "123")
    url, headers, body = build("../../../../etc/passwd")
    assert "../../../../etc/passwd" in url   # slashes kept so path-traversal payloads reach the server


def _ssrf_meta_send(vulnerable=True):
    def send(url, headers, body):
        if vulnerable and "169.254.169.254" in url:
            return {"status": 200, "headers": {}, "location": "", "url": url,
                    "text": "ami-id\ninstance-id\niam/security-credentials/\nlocal-ipv4\nhostname"}
        return {"status": 200, "headers": {}, "text": "ok", "location": "", "url": url}
    return send


def test_ssrf_cloud_metadata_no_oob_detected():
    c = chk.Ssrf()
    point = {"loc": "query", "name": "url", "value": "https://example.com/img.png"}
    build = lambda p: ("https://t.test/fetch?url=" + p, {}, None)
    f = c.run(point, build, _ssrf_meta_send(vulnerable=True), baseline=None, rand="abc", oob=None)
    assert f is not None and f["check"] == "ssrf" and f["severity"] == "high"
    assert "metadata" in f["evidence"].lower()


def test_ssrf_metadata_not_probed_on_non_url_param():
    c = chk.Ssrf()
    point = {"loc": "query", "name": "sort", "value": "asc"}   # not a URL-ish param
    build = lambda p: ("https://t.test/list?sort=" + p, {}, None)
    f = c.run(point, build, _ssrf_meta_send(vulnerable=True), baseline=None, rand="abc", oob=None)
    assert f is None


def test_passive_detects_leaked_secrets_redacted():
    from wyrm.security.audit import passive
    body = (
        "var cfg = {region:'us-east-1'};\n"
        "const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';\n"
        "apiKey: 'sk_live_abcdef....redactme....0123456789';\n"
        "-----BEGIN RSA PRIVATE KEY-----\nMIIExxxx\n-----END RSA PRIVATE KEY-----\n"
    )
    out = passive.check_response("https://app.test/main.js",
                                 {"headers": {"content-type": "application/javascript"}, "status": 200, "text": body})
    titles = [f["title"] for f in out]
    assert any("AWS access key id" in t for t in titles)
    assert any("Private key block" in t for t in titles)
    assert any(f["severity"] == "high" for f in out if f["title"].startswith("Secret exposed"))
    # evidence must be redacted — the full AWS key must not appear in any finding
    assert all("AKIAIOSFODNN7EXAMPLE" not in f["evidence"] for f in out)


def test_passive_detects_cardholder_data_luhn_valid_masked():
    from wyrm.security.audit import passive
    # 4111111111111111 is the canonical Luhn-valid Visa test PAN
    body = '{"user":"jo","card":"4111111111111111","exp":"12/29"}'
    out = passive.check_response("https://shop.test/account",
                                 {"headers": {"content-type": "application/json"}, "status": 200, "text": body})
    pan = [f for f in out if "Cardholder data" in f["title"]]
    assert pan and pan[0]["severity"] == "high"
    assert "4111111111111111" not in pan[0]["evidence"]          # masked
    assert "411111" in pan[0]["evidence"] and "1111" in pan[0]["evidence"]


def test_passive_ignores_non_card_digit_runs():
    from wyrm.security.audit import passive
    # a 16-digit order id that is NOT Luhn-valid must not be flagged
    body = '{"orderId":"1234567812345670000"}'   # too long / invalid prefix
    out = passive.check_response("https://shop.test/o",
                                 {"headers": {"content-type": "application/json"}, "status": 200, "text": body})
    assert not [f for f in out if "Cardholder data" in f["title"]]


def _make_jwt(header: dict, payload: dict) -> str:
    import base64 as _b, json as _j

    def seg(d):
        return _b.urlsafe_b64encode(_j.dumps(d).encode()).rstrip(b"=").decode()
    return f"{seg(header)}.{seg(payload)}.sig"


def test_passive_flags_alg_none_jwt():
    from wyrm.security.audit import passive
    tok = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "admin", "exp": 9999999999})
    out = passive.check_response("https://api.test/token",
                                 {"headers": {"content-type": "application/json"}, "status": 200,
                                  "text": '{"access_token":"' + tok + '"}'})
    assert any("alg:none" in f["title"] for f in out)
    assert any(f["severity"] == "high" for f in out if "alg:none" in f["title"])


def test_passive_flags_jwt_without_exp_low():
    from wyrm.security.audit import passive
    tok = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "u1"})   # no exp
    out = passive.check_response("https://api.test/token",
                                 {"headers": {"content-type": "application/json"}, "status": 200,
                                  "text": '{"token":"' + tok + '"}'})
    assert any("without an expiry" in f["title"] for f in out)


def test_passive_normal_jwt_with_exp_is_quiet():
    from wyrm.security.audit import passive
    tok = _make_jwt({"alg": "RS256", "typ": "JWT"}, {"sub": "u1", "exp": 9999999999})
    out = passive.check_response("https://api.test/token",
                                 {"headers": {"content-type": "application/json"}, "status": 200,
                                  "text": '{"token":"' + tok + '"}'})
    assert not any("JWT" in f["title"] for f in out)


def test_passive_flags_post_form_without_csrf_token():
    from wyrm.security.audit import passive
    body = '<html><body><form method="post" action="/transfer"><input name="amount"><button>Go</button></form></body></html>'
    out = passive.check_response("https://bank.test/pay",
                                 {"headers": {"content-type": "text/html"}, "status": 200, "text": body})
    assert any("anti-CSRF token" in f["title"] for f in out)


def test_passive_post_form_with_token_is_clean():
    from wyrm.security.audit import passive
    body = ('<form method="post"><input type="hidden" name="csrf_token" value="abc123">'
            '<input name="amount"></form>')
    out = passive.check_response("https://bank.test/pay",
                                 {"headers": {"content-type": "text/html"}, "status": 200, "text": body})
    assert not any("anti-CSRF token" in f["title"] for f in out)


def test_passive_get_form_not_flagged_for_csrf():
    from wyrm.security.audit import passive
    body = '<form method="get" action="/search"><input name="q"></form>'
    out = passive.check_response("https://site.test/",
                                 {"headers": {"content-type": "text/html"}, "status": 200, "text": body})
    assert not any("anti-CSRF token" in f["title"] for f in out)


def test_passive_flags_werkzeug_debugger():
    from wyrm.security.audit import passive
    body = "<html><body>Werkzeug Debugger<div>The debugger caught an exception</div></body></html>"
    out = passive.check_response("https://app.test/boom",
                                 {"headers": {"content-type": "text/html"}, "status": 500, "text": body})
    dbg = [f for f in out if "debugger" in f["title"].lower()]
    assert dbg and dbg[0]["severity"] == "high"


def test_passive_flags_phpinfo():
    from wyrm.security.audit import passive
    body = "<title>phpinfo()</title><table><tr><td>PHP Version </td><td>8.1.0</td></tr></table>"
    out = passive.check_response("https://app.test/info.php",
                                 {"headers": {"content-type": "text/html"}, "status": 200, "text": body})
    assert any("phpinfo" in f["title"].lower() for f in out)


def test_passive_normal_error_page_not_flagged_as_debugger():
    from wyrm.security.audit import passive
    body = "<html><body>Sorry, something went wrong. Please try again later.</body></html>"
    out = passive.check_response("https://app.test/err",
                                 {"headers": {"content-type": "text/html"}, "status": 500, "text": body})
    assert not [f for f in out if "debugger" in f["title"].lower() or "phpinfo" in f["title"].lower()]


def test_passive_detects_active_mixed_content():
    from wyrm.security.audit import passive
    body = '<html><head><script src="http://cdn.evil/x.js"></script></head><body>hi</body></html>'
    out = passive.check_response("https://secure.test/",
                                 {"headers": {"content-type": "text/html"}, "status": 200, "text": body})
    mc = [f for f in out if "Mixed content" in f["title"]]
    assert mc and mc[0]["severity"] == "medium"


def test_passive_https_only_resources_no_mixed_content():
    from wyrm.security.audit import passive
    body = '<html><head><script src="https://cdn.ok/x.js"></script><img src="http://cdn/x.png"></head></html>'
    out = passive.check_response("https://secure.test/",
                                 {"headers": {"content-type": "text/html"}, "status": 200, "text": body})
    # an http img is passive mixed content (not flagged by this active-resource check); the https script is fine
    assert not [f for f in out if "Mixed content" in f["title"]]


def test_passive_clean_response_has_no_secret_findings():
    from wyrm.security.audit import passive
    out = passive.check_response("https://app.test/clean.js",
                                 {"headers": {"content-type": "application/javascript",
                                              "content-security-policy": "default-src 'self'",
                                              "x-content-type-options": "nosniff",
                                              "strict-transport-security": "max-age=1"},
                                  "status": 200, "text": "console.log('hello world');"})
    assert not [f for f in out if f["title"].startswith("Secret exposed")]


def test_scan_respects_request_budget():
    from wyrm.security.audit import engine
    calls = [0]

    def send(method, url, headers, body):
        calls[0] += 1
        return {"status": 200, "headers": {}, "text": "ok", "location": "", "url": url}

    req = {"method": "GET", "url": "https://t.test/p?a=1&b=2&c=3&d=4", "headers": {}, "body": ""}
    # a tiny budget must stop the scan early (unbounded this would be hundreds of requests for 4 params x N checks)
    engine.scan(req, send, checks=chk.standard(time_based=False), passive=False, max_requests=5)
    assert calls[0] <= 20, f"budget not honoured: {calls[0]} requests sent"


def test_every_builtin_check_key_has_remediation_advice():
    from wyrm.security.audit import advice
    keys = {c.key for c in chk.standard(time_based=True)}
    keys.add("passive")   # passive response findings share one advice entry
    for k in sorted(keys):
        text, refs = advice.advice(k)
        assert text, f"check key '{k}' has no remediation advice (report would be incomplete)"


def test_fast_and_thorough_sets_match_except_time_based_probes():
    thorough = {type(c).__name__ for c in chk.standard(time_based=True)}
    fast = {type(c).__name__ for c in chk.standard(time_based=False)}
    assert thorough == fast   # same checks; the time-based ones just go inert at Fast (run() returns None)


def test_engine_end_to_end_finds_multiple_vuln_classes():
    """A deliberately vulnerable fake app: reflects input (XSS), errors on a quote (SQLi), and reflects the
    Origin with credentials (CORS). The full engine (insertion points + all checks + passive + request-level)
    should surface all three."""
    from urllib.parse import urlsplit, parse_qsl
    from wyrm.security.audit import engine

    def vuln_send(method, url, headers, body):
        text = "<html><body>"
        H = {}
        for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True):
            text += f"<div>{v}</div>"                       # reflects unescaped -> XSS
            if "'" in v:
                text += "You have an error in your SQL syntax; check the manual that corresponds to your MySQL"
        origin = headers.get("Origin")
        if origin:                                          # reflects arbitrary Origin + credentials -> CORS
            H["access-control-allow-origin"] = origin
            H["access-control-allow-credentials"] = "true"
        return {"status": 200, "headers": H, "text": text + "</body></html>", "location": "", "url": url}

    findings = engine.scan({"method": "GET", "url": "https://vuln.test/page?q=hello", "headers": {}, "body": ""},
                           vuln_send, passive=True)
    found = {f["check"] for f in findings}
    assert "xss" in found, found
    assert "sqli" in found, found
    assert "cors" in found, found


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
