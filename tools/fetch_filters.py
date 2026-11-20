"""Download a snapshot of the Shields filter lists into wyrm/assets/filters/ (run at build time),
so a fresh install blocks ads, trackers, malware and phishing immediately, even before the first update.

    python tools/fetch_filters.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from wyrm.shields import fetch_lists  # noqa: E402

dest = Path(__file__).resolve().parent.parent / "wyrm" / "assets" / "filters"
texts = fetch_lists(dest)
print("filter snapshot:", {k: f"{len(v) // 1024} KB" for k, v in texts.items()})
