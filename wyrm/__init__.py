#------------------------------------------------------------------------------
# Wyrm — wyrm/__init__.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Wyrm (powered by HackPi): a privacy- and security-focused web browser."""
from datetime import date

__version__ = "0.5.0"   # shown to users; change it yourself for a new version line (e.g. 0.1.0)
__build__ = 0           # set by CI (GitHub Actions run number): orders releases that share a version
START_YEAR = 2023  # development started (first public release: 2026)


def _build_meta():
    """(sha, timestamp) written into wyrm/_buildinfo.py by the build scripts; ('', '') when run from source."""
    try:
        from . import _buildinfo  # generated at build time; absent in a source checkout
        return str(getattr(_buildinfo, "SHA", "")), str(getattr(_buildinfo, "BUILD_TIME", ""))
    except Exception:  # noqa: BLE001 - never let a missing/broken build stamp crash startup
        return "", ""


def _git_sha() -> str:
    """Best-effort short commit SHA when running from a git checkout (so 'dev' builds are still identifiable)."""
    try:
        import pathlib
        import subprocess
        r = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=str(pathlib.Path(__file__).parent.parent),
                           capture_output=True, text=True, timeout=3)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:  # noqa: BLE001
        return ""


def version_label() -> str:
    """A version string a tester can pin to an exact build, e.g. '0.5.0 (build 0, 4cc1acd, 2026-11-25 11:17)'
    for a built app, or '0.5.0 (dev, 4cc1acd)' when run from source (QA-H1)."""
    sha, when = _build_meta()
    if sha or when or __build__:
        parts = [f"build {__build__}"]
        if sha:
            parts.append(sha)
        if when:
            parts.append(when)
        return f"{__version__} (" + ", ".join(parts) + ")"
    sha = _git_sha()
    return f"{__version__} (dev{', ' + sha if sha else ''})"


def years() -> str:
    """'2023–<current year>', evaluated each time so it rolls over on New Year without a rebuild."""
    return f"{START_YEAR}–{date.today().year}"


def __getattr__(name):  # __copyright__ stays current too
    if name == "__copyright__":
        return f"Copyright (c) {years()} ByKh R&D Group"
    raise AttributeError(name)
