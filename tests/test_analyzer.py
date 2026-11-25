#------------------------------------------------------------------------------
# Wyrm — tests/test_analyzer.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""QA-H5: a credential inside an HTML comment is a real leak (high), not just an 'Interesting HTML comment'."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wyrm.security.analyzer import check_page  # noqa: E402


def test_secret_in_html_comment_is_high():
    page = {"comments": ["<!-- TODO remove: api_key=AKIAIOSFODNN7EXAMPLE password=hunter2 -->"]}
    out = check_page(page)
    aws = [i for i in out if "AWS access key id" in i["title"] and "HTML comment" in i["title"]]
    assert aws and aws[0]["severity"] == "high"
    # the raw key must not be stored in full
    assert all("AKIAIOSFODNN7EXAMPLE" not in i["evidence"] for i in aws)


def test_plain_interesting_comment_still_info():
    page = {"comments": ["<!-- TODO: refactor the admin dashboard -->"]}
    out = check_page(page)
    info = [i for i in out if i["title"] == "Interesting HTML comment"]
    assert info and info[0]["severity"] == "info"


def test_boring_comment_is_silent():
    page = {"comments": ["<!-- build 1234 -->"]}
    out = check_page(page)
    assert not [i for i in out if "comment" in i["title"].lower()]


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
