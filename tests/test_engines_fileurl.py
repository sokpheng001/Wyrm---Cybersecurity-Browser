#------------------------------------------------------------------------------
# Wyrm — tests/test_engines_fileurl.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Local file paths typed in the address bar become valid, properly-encoded file:// URLs (spaces etc.)."""
from wyrm import engines

BS = chr(92)   # backslash, kept out of source to dodge escaping confusion


def test_windows_path_with_spaces_is_encoded():
    p = r"C:\Users\Kim\Pictures\sokpkheng document to krorea"
    assert engines.resolve(p) == "file:///C:/Users/Kim/Pictures/sokpkheng%20document%20to%20krorea"


def test_windows_path_round_trips_through_qurl():
    from PySide6.QtCore import QUrl
    p = r"C:\Program Files\My App\index.html"
    u = QUrl(engines.resolve(p))
    assert u.isValid() and u.toLocalFile() == "C:/Program Files/My App/index.html"


def test_special_characters_are_percent_encoded():
    out = engines.resolve(r"C:\tmp\a#b&c d.txt")
    assert "%23" in out and "%26" in out and "%20" in out and out.startswith("file:///C:/tmp/")


def test_forward_slash_drive_path_also_works():
    assert engines.resolve("C:/Users/Kim/my file.txt") == "file:///C:/Users/Kim/my%20file.txt"


def test_unc_path_with_spaces():
    unc = BS + BS + "server" + BS + "share" + BS + "my docs"
    assert engines.resolve(unc) == "file://server/share/my%20docs"


def test_explicit_file_scheme_is_left_alone():
    assert engines.resolve("file:///C:/already/encoded%20path").startswith("file:///C:/already/")
