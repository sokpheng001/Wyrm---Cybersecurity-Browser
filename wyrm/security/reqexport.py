#------------------------------------------------------------------------------
# Wyrm — wyrm/security/reqexport.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Turn one HTTP request into something else, offline (nothing here sends a request):

    parse_raw(text)      a raw HTTP request ("POST /a HTTP/1.1\\nHost: …") -> request dict
    to_code(req, lang)   the same request as cURL / Python requests / JavaScript fetch / PowerShell

A request dict is {"method", "url", "headers" (dict), "body" (str)}. This lets someone reproduce a request they
captured in the browser from a script or a terminal, the way Repeater/DevTools "Copy as …" does."""
from __future__ import annotations

import json

from .tools import to_curl

LANGS = ["cURL", "Python (requests)", "JavaScript (fetch)", "PowerShell"]

# headers a client computes for itself; exporting them only breaks the copy (wrong length, stale host after edits)
_SKIP = {"content-length", "host", "connection", "accept-encoding"}


def parse_raw(text: str, scheme: str = "https") -> dict:
    """Parse a raw HTTP/1.x request. An absolute URL on the request line wins over the Host header.
    Raises ValueError when there is no usable request line."""
    text = (text or "").replace("\r\n", "\n").lstrip("\n")
    head, _sep, body = text.partition("\n\n")
    lines = head.split("\n")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("first line must look like: GET /path HTTP/1.1")
    method, target = parts[0].upper(), parts[1]
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    if target.startswith(("http://", "https://")):
        url = target
    else:
        host = next((v for k, v in headers.items() if k.lower() == "host"), "")
        if not host:
            raise ValueError("no Host header and the request line has no full URL")
        url = f"{scheme}://{host}{target if target.startswith('/') else '/' + target}"
    return {"method": method, "url": url, "headers": headers, "body": body}


def _export_headers(req) -> dict:
    return {k: v for k, v in (req.get("headers") or {}).items() if k.lower() not in _SKIP}


def _s(s: str) -> str:
    return json.dumps(s, ensure_ascii=False)   # a valid Python (and JS) double-quoted string literal


def _ps(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"   # PowerShell single-quoted: only ' needs doubling


def to_code(req: dict, lang: str) -> str:
    method = (req.get("method") or "GET").upper()
    url, body = req.get("url", ""), req.get("body") or ""
    hdrs = _export_headers(req)
    if lang == "cURL":
        return to_curl(method, url, hdrs, body or None)
    if lang == "Python (requests)":
        out = ["import requests", "", f"url = {_s(url)}", "headers = {"]
        out += [f"    {_s(k)}: {_s(v)}," for k, v in hdrs.items()]
        out.append("}")
        call = f"r = requests.request({_s(method)}, url, headers=headers"
        if body:
            out.append(f"data = {_s(body)}")
            call += ", data=data.encode()"
        out += [call + ")", "print(r.status_code)", "print(r.text)"]
        return "\n".join(out)
    if lang == "JavaScript (fetch)":
        opts = [f"  method: {_s(method)},", "  headers: {"]
        opts += [f"    {_s(k)}: {_s(v)}," for k, v in hdrs.items()]
        opts.append("  },")
        if body and method not in ("GET", "HEAD"):
            opts.append(f"  body: {_s(body)},")
        return (f"fetch({_s(url)}, {{\n" + "\n".join(opts) + "\n})\n"
                "  .then(r => r.text()).then(t => console.log(t));")
    if lang == "PowerShell":
        out = ["$headers = @{"]
        out += [f"    {_ps(k)} = {_ps(v)}" for k, v in hdrs.items() if k.lower() != "content-type"]
        out.append("}")
        call = f"Invoke-WebRequest -Uri {_ps(url)} -Method {method} -Headers $headers"
        ct = next((v for k, v in hdrs.items() if k.lower() == "content-type"), "")
        if ct:   # PowerShell takes Content-Type as its own parameter, not via the headers hashtable
            call += f" -ContentType {_ps(ct)}"
        if body:
            out.append(f"$body = {_ps(body)}")
            call += " -Body $body"
        out.append(call + " -UseBasicParsing")
        return "\n".join(out)
    raise ValueError(f"unknown language: {lang}")
