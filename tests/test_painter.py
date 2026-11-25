#------------------------------------------------------------------------------
# Wyrm — tests/test_painter.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""B4: no QPainter is left active — every use is a `with` block (ended even when painting raises), so a painter
can't survive inside a stored traceback until Python's shutdown and crash in QPainter::end()."""
import ast
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


def test_every_qpainter_is_a_context_manager():
    bad = []
    for f in (ROOT / "wyrm").rglob("*.py"):
        if "bin" in f.parts:
            continue
        tree = ast.parse(f.read_text(encoding="utf-8"))
        with_calls = {id(i.context_expr) for n in ast.walk(tree) if isinstance(n, ast.With) for i in n.items}
        for n in ast.walk(tree):
            if (isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", "")) == "QPainter"
                    and id(n) not in with_calls):
                bad.append(f"{f.relative_to(ROOT)}:{n.lineno}")
            if isinstance(n, ast.Assign) and any(isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name)
                                                 and t.value.id == "self" for t in n.targets) \
                    and isinstance(n.value, ast.Call) and getattr(n.value.func, "id", "") == "QPainter":
                bad.append(f"{f.relative_to(ROOT)}:{n.lineno} (painter stored on self)")
    assert not bad, bad


def test_painter_is_ended_when_painting_raises():
    pytest.importorskip("PySide6.QtGui")
    from PySide6.QtGui import QGuiApplication, QPainter, QPixmap
    QGuiApplication.instance() or QGuiApplication([])
    pm = QPixmap(8, 8)
    held = {}
    with pytest.raises(ZeroDivisionError):
        with QPainter(pm) as p:
            held["p"] = p
            1 / 0
    assert not held["p"].isActive()          # ended despite the exception (and the traceback holding it)
