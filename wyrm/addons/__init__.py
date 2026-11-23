#------------------------------------------------------------------------------
# Wyrm — wyrm/addons/__init__.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Sopi, Kwan
#------------------------------------------------------------------------------
"""Wyrm Add-ons: user/third-party Python plugins that extend the browser (Burp BApp / Caido plugin style).

An add-on is a folder under <profile>/addons/<id>/ with a manifest.json and an entry module exposing
`register(ctx)`. See wyrm/addons/api.py (AddonContext) for what an add-on can do, and ADDONS.md for the guide.
"""
from . import api, loader  # noqa: F401
