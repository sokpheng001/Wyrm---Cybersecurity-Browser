"""Wyrm (powered by HackPi): a privacy- and security-focused web browser."""
from datetime import date

__version__ = "0.0.1"
START_YEAR = 2023  # development started (first public release: 2026)


def years() -> str:
    """'2023–<current year>', evaluated each time so it rolls over on New Year without a rebuild."""
    return f"{START_YEAR}–{date.today().year}"


def __getattr__(name):  # __copyright__ stays current too
    if name == "__copyright__":
        return f"Copyright (c) {years()} ByKh R&D Group"
    raise AttributeError(name)
