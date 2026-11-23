#------------------------------------------------------------------------------
# Wyrm — wyrm/security/workflows.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Workflows — Caido-style automation pipelines that run on live proxy traffic.

A workflow is a named, ordered pipeline of steps applied to every request and/or response flowing through the
intercepting proxy (optionally limited to URLs containing some text). Steps so far:

    set-header     set/replace a request or response header
    remove-header  drop a request or response header
    replace        regex find/replace in the header block or body of a request or response
    set-status     force a response status code

Because workflows run inside the proxy, they apply to HTTPS too. They persist to workflows.json in the profile.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from . import mitm

STEP_TYPES = ("set-header", "remove-header", "replace", "set-status")


def _matches_scope(scope: str, url: str) -> bool:
    return (not scope) or (scope.lower() in url.lower())


def _set_header(headers: list, name: str, value: str):
    low = name.lower()
    out = [(k, v) for k, v in headers if k.lower() != low]
    out.append((name, value))
    headers[:] = out


def _remove_header(headers: list, name: str):
    low = name.lower()
    headers[:] = [(k, v) for k, v in headers if k.lower() != low]


class WorkflowEngine:
    """Holds the workflows, applies them on proxy threads, and persists them."""

    def __init__(self):
        self.workflows: list[dict] = []
        self.path: Path | None = None
        self.notify = None          # optional callback(name) when a workflow fires (for the UI)

    # -------------------------------------------------- persistence
    def load(self, path: Path):
        self.path = path
        try:
            self.workflows = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(self.workflows, list):
                self.workflows = []
        except (OSError, ValueError):
            self.workflows = []
        for wf in self.workflows:
            wf.setdefault("hits", 0)
        return self

    def save(self):
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.workflows, indent=2), encoding="utf-8")
        except OSError:
            pass

    # -------------------------------------------------- install on the proxy
    def install(self, proxy):
        if self._req not in proxy.request_rewriters:
            proxy.request_rewriters.append(self._req)
        if self._resp not in proxy.response_rewriters:
            proxy.response_rewriters.append(self._resp)

    # -------------------------------------------------- apply (proxy worker threads)
    def _enabled(self):
        return [wf for wf in self.workflows if wf.get("enabled", True)]

    def _req(self, req: dict):
        url = f"{req['scheme']}://{req['host']}{req['path']}"
        for wf in self._enabled():
            if not _matches_scope(wf.get("scope", ""), url):
                continue
            fired = False
            for step in wf.get("steps", []):
                if step.get("where", "req") != "req":
                    continue
                if self._apply_req(step, req):
                    fired = True
            if fired:
                self._fire(wf)

    def _resp(self, flow: dict):
        url = flow.get("url", "")
        for wf in self._enabled():
            if not _matches_scope(wf.get("scope", ""), url):
                continue
            fired = False
            for step in wf.get("steps", []):
                if step.get("where", "req") != "resp":
                    continue
                if self._apply_resp(step, flow):
                    fired = True
            if fired:
                self._fire(wf)

    def _apply_req(self, step, req) -> bool:
        t = step.get("type")
        if t == "set-header":
            _set_header(req["headers"], step["name"], step.get("value", ""))
            return True
        if t == "remove-header":
            _remove_header(req["headers"], step["name"])
            return True
        if t == "replace":
            return self._replace(step, req, is_resp=False)
        return False

    def _apply_resp(self, step, flow) -> bool:
        t = step.get("type")
        if t == "set-header":
            _set_header(flow["resp_headers"], step["name"], step.get("value", ""))
            return True
        if t == "remove-header":
            _remove_header(flow["resp_headers"], step["name"])
            return True
        if t == "set-status":
            try:
                flow["status"] = int(step["value"])
                flow["reason"] = ""
                return True
            except (ValueError, KeyError):
                return False
        if t == "replace":
            return self._replace(step, flow, is_resp=True)
        return False

    def _replace(self, step, obj, is_resp) -> bool:
        try:
            rx = re.compile(step["find"])
        except (re.error, KeyError):
            return False
        repl = step.get("repl", "")
        part = step.get("part", "body")
        hdr_key = "resp_headers" if is_resp else "headers"
        body_key = "resp_body" if is_resp else "body"
        if part == "header":
            changed = False
            new = []
            for k, v in obj[hdr_key]:
                nv, n = rx.subn(repl, v)
                new.append((k, nv))
                changed = changed or bool(n)
            if changed:
                obj[hdr_key] = new
            return changed
        # body
        raw = obj.get(body_key) or b""
        if is_resp:
            raw = mitm.inflate(obj["resp_headers"], raw)
        text = raw.decode("utf-8", "replace")
        new_text, n = rx.subn(repl, text)
        if not n:
            return False
        new_body = new_text.encode("utf-8", "replace")
        obj[body_key] = new_body
        if is_resp:   # body is now plain: drop the old compression / length so the browser reads it
            _remove_header(obj["resp_headers"], "content-encoding")
            _remove_header(obj["resp_headers"], "content-length")
        return True

    def _fire(self, wf):
        wf["hits"] = wf.get("hits", 0) + 1
        if self.notify is not None:
            try:
                self.notify(wf.get("name", ""))
            except Exception:  # noqa: BLE001
                pass
