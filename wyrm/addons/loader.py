#------------------------------------------------------------------------------
# Wyrm — wyrm/addons/loader.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Sopi, Kwan
#------------------------------------------------------------------------------
"""Discover, enable/disable and load Wyrm add-ons from <profile>/addons/<id>/.

Each add-on folder has a manifest.json ({name, version, entry, author, description, permissions}) and the entry
module (default main.py) with a top-level register(ctx). Only add-ons the user has enabled are loaded; a broken
add-on is isolated so it can never stop the browser from starting.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from .api import AddonContext

_loaded = False   # hooks register process-wide once (first window), so extra windows don't double-register


def addons_root(data_dir) -> Path:
    return Path(data_dir) / "addons"


def discover(data_dir) -> list[dict]:
    """Every add-on found on disk (enabled or not), newest manifest fields plus _id/_dir."""
    out = []
    root = addons_root(data_dir)
    if not root.is_dir():
        return out
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        mf = d / "manifest.json"
        if not mf.is_file():
            continue
        try:
            meta = json.loads(mf.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(meta, dict):
            continue
        meta["_id"] = d.name
        meta["_dir"] = str(d)
        out.append(meta)
    return out


def is_enabled(settings, addon_id: str) -> bool:
    return settings.value(f"addons/enabled/{addon_id}", False, type=bool)


def set_enabled(settings, addon_id: str, on: bool):
    settings.setValue(f"addons/enabled/{addon_id}", bool(on))
    settings.sync()


def load_all(win) -> list[dict]:
    """Load every enabled add-on. Returns a status row per add-on: {meta, ok, error}. Idempotent per process."""
    global _loaded
    rows = []
    enabled = [m for m in discover(win.data_dir) if is_enabled(win.settings, m["_id"])]
    for meta in enabled:
        if _loaded:   # hooks already attached by the first window; don't double-register
            rows.append({"meta": meta, "ok": True, "error": None})
            continue
        try:
            _load_one(win, meta)
            rows.append({"meta": meta, "ok": True, "error": None})
        except Exception as e:  # noqa: BLE001 - never let an add-on break startup
            rows.append({"meta": meta, "ok": False, "error": str(e)})
    _loaded = True
    win._addon_rows = rows
    return rows


def _load_one(win, meta: dict):
    d = Path(meta["_dir"])
    entry = meta.get("entry", "main.py")
    main_py = d / entry
    if not main_py.is_file():
        raise FileNotFoundError(f"entry {entry} not found")
    ctx = AddonContext(win, meta)
    modname = f"wyrm_addon_{meta['_id']}"
    spec = importlib.util.spec_from_file_location(modname, main_py)
    if spec is None or spec.loader is None:
        raise ImportError("could not load entry module")
    mod = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(d))   # so a multi-file add-on can import its own siblings
    try:
        sys.modules[modname] = mod
        spec.loader.exec_module(mod)
        if hasattr(mod, "register"):
            mod.register(ctx)
    finally:
        try:
            sys.path.remove(str(d))
        except ValueError:
            pass
    for name, widget in ctx._tabs:   # add-on UI goes into the Security panel under ADD-ONS
        try:
            win.security.add_addon_tab(name, widget)
        except Exception:  # noqa: BLE001
            ctx.log(f"could not add tab {name}")
    win.__dict__.setdefault("_addon_ctxs", []).append(ctx)
    return ctx
