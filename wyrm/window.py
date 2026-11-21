#------------------------------------------------------------------------------
# Wyrm — wyrm/window.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Compatibility shim — see wyrm/mainwindow/."""
# Compatibility shim: the main window now lives in wyrm/mainwindow/ (split into focused modules).
from .browser.interceptor import TrafficInterceptor  # noqa: F401
from .browser.scripts import CITESEE_JS, COLLECT_JS, FINGERPRINT_JS, YOUTUBE_JS  # noqa: F401
from .browser.view import BrowserView  # noqa: F401
from .mainwindow.window import MainWindow  # noqa: F401
from .ui.common import APP, HOME, ICONS, make_icon  # noqa: F401
from .ui.update_runner import Updater  # noqa: F401
