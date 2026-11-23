#------------------------------------------------------------------------------
# Wyrm — wyrm/security/har.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Sopi, Kwan
#------------------------------------------------------------------------------
"""Export captured proxy flows to HAR 1.2 (HTTP Archive) — the standard JSON format other tools import."""
from __future__ import annotations

import json
from datetime import datetime
from urllib.parse import parse_qsl, urlsplit

from . import mitm


def _nv(pairs):
    return [{"name": str(k), "value": str(v)} for k, v in pairs]


def _header(pairs, name):
    name = name.lower()
    return next((v for k, v in pairs if k.lower() == name), "")


def flows_to_har(flows: list) -> dict:
    from .. import __version__
    entries = []
    for fl in flows:
        url = fl.get("url", "")
        ts = fl.get("ts")
        started = (datetime.fromtimestamp(ts) if ts else datetime.now()).astimezone().isoformat()
        req_headers = fl.get("req_headers", []) or []
        resp_headers = fl.get("resp_headers", []) or []
        req_body = fl.get("req_body") or b""
        req_text = bytes(req_body).decode("utf-8", "replace") if isinstance(req_body, (bytes, bytearray)) else str(req_body)
        resp_text = mitm.decode_body(resp_headers, fl.get("resp_body") or b"")
        request = {
            "method": fl.get("method", "GET"), "url": url, "httpVersion": "HTTP/1.1",
            "headers": _nv(req_headers),
            "queryString": _nv(parse_qsl(urlsplit(url).query, keep_blank_values=True)),
            "cookies": [], "headersSize": -1, "bodySize": len(req_body),
        }
        if req_text:
            request["postData"] = {"mimeType": _header(req_headers, "content-type"), "text": req_text}
        entries.append({
            "startedDateTime": started,
            "time": fl.get("ms", 0),
            "request": request,
            "response": {
                "status": fl.get("status", 0), "statusText": fl.get("reason", "") or "", "httpVersion": "HTTP/1.1",
                "headers": _nv(resp_headers), "cookies": [],
                "content": {"size": len(resp_text), "mimeType": _header(resp_headers, "content-type"), "text": resp_text},
                "redirectURL": _header(resp_headers, "location"), "headersSize": -1,
                "bodySize": len(fl.get("resp_body") or b""),
            },
            "cache": {},
            "timings": {"send": 0, "wait": fl.get("ms", 0), "receive": 0},
        })
    return {"log": {"version": "1.2", "creator": {"name": "Wyrm Browser", "version": __version__}, "entries": entries}}


def save_har(flows: list, path) -> int:
    """Write flows as HAR to `path`; returns the number of entries written."""
    har = flows_to_har(flows)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(har, fh, indent=2)
    return len(har["log"]["entries"])
