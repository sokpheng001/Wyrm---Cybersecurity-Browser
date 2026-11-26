#------------------------------------------------------------------------------
# Wyrm — wyrm/navpolicy.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Navigation policy: decide whether a navigation to a given scheme is allowed (SEC-10).

A *web page* must not be able to navigate the browser to a privileged, local-filesystem or in-URL-script address;
only the user (address bar / history) or Wyrm's own wyrm:// chrome may. Kept Qt-free so it is unit-testable.
"""
from __future__ import annotations

# Schemes a web page may never reach on its own. data: is guarded only for a *top-level* navigation (data: images
# and sub-frames stay allowed); file:// is the local filesystem; javascript: is in-URL script; wyrm:// is chrome.
_GUARDED = ("wyrm", "file", "javascript")


def should_block(target_scheme: str, *, is_main_frame: bool, user_driven: bool, current_scheme: str) -> bool:
    """True when a navigation must be blocked.

    target_scheme   scheme of the URL being navigated to (lower-cased or not)
    is_main_frame   whether this is a top-level navigation (vs a sub-frame)
    user_driven     the navigation came from the address bar, history (back/forward) or a reload
    current_scheme  scheme of the page that initiated it ('' = initial/blank load)
    """
    scheme = (target_scheme or "").lower()
    guarded = scheme in _GUARDED or (scheme == "data" and is_main_frame)
    if not guarded:
        return False
    cur = (current_scheme or "").lower()
    from_chrome = cur in ("wyrm", "")
    # A page already loaded from the local filesystem may browse within it: clicking into a folder in a
    # directory listing, or a link to another local file, is normal. The guard exists to stop a *web* page
    # (http/https) reaching file://, not to stop local pages linking to local pages.
    same_local = scheme == "file" and cur == "file"
    return not (user_driven or from_chrome or same_local)
