#------------------------------------------------------------------------------
# Wyrm — wyrm/addons/api.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Sopi, Kwan
#------------------------------------------------------------------------------
"""The Add-on API: an AddonContext is passed to each add-on's register(ctx).

An add-on can:
  - rewrite requests / responses on live proxy traffic (ctx.on_request / ctx.on_response),
  - watch responses passively (ctx.on_response_observed),
  - add its own tab to the Security panel (ctx.add_tab),
  - file findings (ctx.add_finding), toast, log, and keep small persistent storage (ctx.storage / ctx.save).

Add-ons run in-process as trusted Python (the user approves each one before it is enabled), so ctx.win gives
full access when needed. Hooks that touch live traffic require the intercepting proxy to be on.
"""
from __future__ import annotations

import json
import time
from pathlib import Path


class AddonContext:
    """Passed to an add-on's register(ctx). Methods register hooks / UI; attributes expose state + storage."""

    def __init__(self, win, meta: dict):
        self.win = win
        self.meta = meta
        self.name = meta.get("name") or meta.get("_id") or "add-on"
        self.id = meta.get("_id", self.name)
        self._logs: list[str] = []
        self._tabs: list[tuple] = []
        self._store_path = Path(win.data_dir) / "addons" / self.id / "storage.json"
        self.storage = self._load_storage()

    # -------------------------------------------------- traffic hooks (need the intercepting proxy)
    def on_request(self, fn):
        """fn(req: dict) -> None — mutate method/path/headers/body before the request is sent."""
        self._attach("request_rewriters", fn)

    def on_response(self, fn):
        """fn(flow: dict) -> None — mutate status/resp_headers/resp_body before the page sees it."""
        self._attach("response_rewriters", fn)

    def on_response_observed(self, fn):
        """fn(flow: dict) -> None — passive; called after each response (no mutation expected)."""
        self._attach("response_observers", fn)

    def _attach(self, listname, fn):
        from ..security import mitm
        if mitm.ACTIVE is not None:
            getattr(mitm.ACTIVE, listname).append(fn)
        else:
            self.log("proxy is off — this traffic hook will apply when the intercepting proxy is on")

    # -------------------------------------------------- UI
    def add_tab(self, name: str, widget):
        """Add a tab (any QWidget) to the Security panel under ADD-ONS."""
        self._tabs.append((name, widget))

    def add_finding(self, **kwargs):
        try:
            self.win.add_finding_dialog(**kwargs)
        except Exception:  # noqa: BLE001
            self.log("add_finding failed (no engagement?)")

    def toast(self, msg: str, ms: int = 4000):
        try:
            self.win.toast(msg, ms)
        except Exception:  # noqa: BLE001
            pass

    # -------------------------------------------------- misc
    def log(self, msg: str):
        self._logs.append(f"{time.strftime('%H:%M:%S')} · {msg}")
        del self._logs[:-500]

    def save(self):
        try:
            self._store_path.parent.mkdir(parents=True, exist_ok=True)
            self._store_path.write_text(json.dumps(self.storage), encoding="utf-8")
        except OSError:
            pass

    def _load_storage(self) -> dict:
        try:
            return json.loads(self._store_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
