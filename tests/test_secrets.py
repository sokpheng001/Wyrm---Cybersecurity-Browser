#------------------------------------------------------------------------------
# Wyrm — tests/test_secrets.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""QA-H4: one shared secret detector. The three PREFIX_SECRET_SUFFIX snippets that used to slip past the generic
rule must now be found by all three call sites (Overview analyzer, Scanner/JS recon, Audit passive) with the
same name and severity."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wyrm.security import jsrecon, secrets  # noqa: E402
from wyrm.security.audit import passive      # noqa: E402

SNIPPETS = [
    'var SECRET_TOKEN = "sk_test_51Hxxxx0123456789";',
    'var DB_PASSWORD = "hunter2hunter2hunter2";',
    'const API_SECRET_KEY = "abcdef0123456789abcd";',
]


def test_shared_detector_finds_each_snippet():
    for snip in SNIPPETS:
        hits = secrets.find_secrets(snip)
        assert hits, f"missed: {snip}"
        assert hits[0][0] == "Hard-coded secret" and hits[0][2] == "medium"


def test_jsrecon_finds_each_snippet():
    for snip in SNIPPETS:
        hits = jsrecon.find_secrets(snip)
        assert any(n == "Hard-coded secret" and sev == "medium" for n, _s, sev in hits), f"jsrecon missed: {snip}"


def test_passive_finds_each_snippet():
    for snip in SNIPPETS:
        out = passive.check_response("https://t/app.js",
                                     {"headers": {"content-type": "application/javascript"}, "status": 200,
                                      "text": snip})
        found = [f for f in out if f["title"].startswith("Secret exposed")]
        assert found, f"passive missed: {snip}"
        assert found[0]["severity"] == "medium"


def test_name_and_severity_agree_across_tools():
    snip = SNIPPETS[0]
    shared = secrets.find_secrets(snip)[0]
    js = jsrecon.find_secrets(snip)[0]
    assert (shared[0], shared[2]) == (js[0], js[2])


def test_brand_patterns_and_placeholder_skip():
    assert secrets.find_secrets("key=AKIAIOSFODNN7EXAMPLE")[0][2] == "high"        # AWS -> high
    assert secrets.find_secrets('api_key = "changeme"') == []                       # placeholder skipped
    assert secrets.find_secrets('token: "process.env.TOKEN"') == []                 # env ref skipped


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
