#------------------------------------------------------------------------------
# Wyrm — wyrm/security_panel.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Compatibility shim — see wyrm/panels/."""
# Compatibility shim: the Security panel now lives in wyrm/panels/ (one module per tab).
from .panels.common import HeaderHighlighter, PAGEINFO_JS, SEV_COLOR, STATUS_COLOR, mono, sev_badge  # noqa: F401
from .panels.dom import DomTab  # noqa: F401
from .panels.findings import FindingsTab  # noqa: F401
from .panels.intruder import IntruderTab  # noqa: F401
from .panels.overview import OverviewTab  # noqa: F401
from .panels.panel import SecurityPanel  # noqa: F401
from .panels.scanner import ScannerTab  # noqa: F401
from .panels.recon import ReconTab  # noqa: F401
from .panels.shields import ShieldsTab  # noqa: F401
from .panels.sitemap import SiteMapTab  # noqa: F401
from .panels.tools import ToolsTab  # noqa: F401
from .panels.traffic import TrafficFilter, TrafficModel, TrafficTab  # noqa: F401
