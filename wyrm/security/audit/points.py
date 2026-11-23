#------------------------------------------------------------------------------
# Wyrm — wyrm/security/audit/points.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Insertion points: parse a request into the places a payload can go, each with a builder that rebuilds the
request with a given value. Covers URL query params, form and JSON body fields, cookies, and a safe set of
headers. Each point is (meta, build) where meta = {"loc", "name", "value"} and build(payload) -> (url, headers, body).
"""
from __future__ import annotations

import json
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

# headers worth fuzzing (reflected into pages / used by apps); fuzzed only, never structural headers like Host
SAFE_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For", "X-Forwarded-Host", "Origin")


def _is_form(headers: dict) -> bool:
    ct = _ct(headers)
    return "application/x-www-form-urlencoded" in ct


def _is_json(headers: dict) -> bool:
    return "application/json" in _ct(headers)


def _ct(headers: dict) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return str(v).lower()
    return ""


def insertion_points(method: str, url: str, headers: dict, body) -> list[tuple]:
    """Return [(meta, build), …]. build(payload) -> (url, headers, body) with that one spot set to payload."""
    headers = dict(headers or {})
    body = body if isinstance(body, str) else (body.decode("utf-8", "replace") if body else "")
    points: list[tuple] = []

    # ---- URL query parameters
    parts = urlsplit(url)
    q = parse_qsl(parts.query, keep_blank_values=True)
    for i, (k, v) in enumerate(q):
        def build(payload, i=i):
            nq = list(q)
            nq[i] = (nq[i][0], payload)
            return urlunsplit(parts._replace(query=urlencode(nq))), dict(headers), body
        points.append(({"loc": "query", "name": k, "value": v}, build))

    # ---- form body
    if _is_form(headers) and body:
        fb = parse_qsl(body, keep_blank_values=True)
        for i, (k, v) in enumerate(fb):
            def build(payload, i=i):
                nb = list(fb)
                nb[i] = (nb[i][0], payload)
                return url, dict(headers), urlencode(nb)
            points.append(({"loc": "body-form", "name": k, "value": v}, build))

    # ---- JSON body (string/number leaves, dotted paths)
    if _is_json(headers) and body:
        try:
            doc = json.loads(body)
        except ValueError:
            doc = None
        if doc is not None:
            for path, val in _json_leaves(doc):
                def build(payload, path=path):
                    doc2 = json.loads(body)
                    _json_set(doc2, path, payload)
                    return url, dict(headers), json.dumps(doc2)
                points.append(({"loc": "json", "name": ".".join(map(str, path)), "value": str(val)}, build))

    # ---- cookies
    cookie_hdr = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
    if cookie_hdr:
        jar = [c.strip() for c in cookie_hdr.split(";") if "=" in c]
        pairs = [(c.split("=", 1)[0], c.split("=", 1)[1]) for c in jar]
        for i, (k, v) in enumerate(pairs):
            def build(payload, i=i):
                np = list(pairs)
                np[i] = (np[i][0], payload)
                h = dict(headers)
                for hk in list(h):
                    if hk.lower() == "cookie":
                        h[hk] = "; ".join(f"{a}={b}" for a, b in np)
                return url, h, body
            points.append(({"loc": "cookie", "name": k, "value": v}, build))

    # ---- headers (safe set): fuzz present ones; always add X-Forwarded-For if missing
    present = {k.lower(): k for k in headers}
    for name in SAFE_HEADERS:
        real = present.get(name.lower())
        if real is None and name != "X-Forwarded-For":
            continue
        cur = headers.get(real, "") if real else ""

        def build(payload, name=name, real=real):
            h = dict(headers)
            h[real or name] = payload
            return url, h, body
        points.append(({"loc": "header", "name": name, "value": cur}, build))

    return points


def _json_leaves(doc, path=()):
    out = []
    if isinstance(doc, dict):
        for k, v in doc.items():
            out += _json_leaves(v, path + (k,))
    elif isinstance(doc, list):
        for i, v in enumerate(doc):
            out += _json_leaves(v, path + (i,))
    elif isinstance(doc, (str, int, float)) and not isinstance(doc, bool):
        out.append((path, doc))
    return out


def _json_set(doc, path, value):
    for key in path[:-1]:
        doc = doc[key]
    doc[path[-1]] = value
