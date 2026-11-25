#------------------------------------------------------------------------------
# Wyrm — examples/addons/permissions-policy-check/main.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Example Wyrm add-on: register a custom scanner check via ctx.add_scan_check().

Install: copy this folder into your Wyrm profile's `addons/` directory, then enable it in
Security → Add-ons. Its check then runs with the built-in checks on every Fast/Thorough scan.

A check is any object with run(...) and/or run_request(...) returning a finding dict or None:
  run(point, build, send, baseline, rand, oob)                       — once per insertion point
  run_request(method, url, headers, body, send, baseline, rand, oob) — once per request
`send(url, headers, body)` performs one in-scope request. Keep checks safe and non-destructive.
"""


class PermissionsPolicyCheck:
    key = "addon-permissions-policy"
    title = "Missing Permissions-Policy header"
    severity = "info"

    def run_request(self, method, url, headers, body, send, baseline, rand, oob=None):
        # Reuse the response the engine already fetched (baseline) — no extra request needed.
        resp = baseline
        if not resp:
            return None
        present = {k.lower() for k in resp.get("headers", {})}
        if "permissions-policy" in present:
            return None
        return {
            "check": self.key, "title": self.title, "severity": self.severity, "confidence": "certain",
            "loc": "response", "param": "", "payload": "",
            "evidence": "No Permissions-Policy header — powerful browser features (camera, microphone, "
                        "geolocation, etc.) are not restricted for this page.",
            "status": resp.get("status"), "url": url,
        }


def register(ctx):
    """Wyrm calls this once when the add-on is enabled."""
    ctx.add_scan_check(PermissionsPolicyCheck())
    ctx.log("Permissions-Policy checker registered")
