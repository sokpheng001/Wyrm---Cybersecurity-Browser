#------------------------------------------------------------------------------
# Wyrm — wyrm/__init__.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Wyrm (powered by HackPi): a privacy- and security-focused web browser."""
from datetime import date

__version__ = "0.0.8"   # shown to users; change it yourself for a new version line (e.g. 0.1.0)
__build__ = 0           # set by CI (GitHub Actions run number): orders releases that share a version
START_YEAR = 2023  # development started (first public release: 2026)


def version_label() -> str:
    """'0.0.1 (build 57)' for released builds, '0.0.1 (dev)' when run from source."""
    return f"{__version__} (build {__build__})" if __build__ else f"{__version__} (dev)"


def years() -> str:
    """'2023–<current year>', evaluated each time so it rolls over on New Year without a rebuild."""
    return f"{START_YEAR}–{date.today().year}"


def __getattr__(name):  # __copyright__ stays current too
    if name == "__copyright__":
        return f"Copyright (c) {years()} ByKh R&D Group"
    raise AttributeError(name)
