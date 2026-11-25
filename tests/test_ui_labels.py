#------------------------------------------------------------------------------
# Wyrm — tests/test_ui_labels.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""QA-M4: a literal '&' in a mnemonic-parsing widget label renders as an underscore ('API & WebSocket' ->
'API _WebSocket'). AST-scan the source for string labels passed to such widgets and fail on any lone '&'."""
import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WYRM = os.path.join(ROOT, "wyrm")

# widget constructors whose first string argument is a mnemonic-parsing label
_WIDGETS = {"QPushButton", "QCheckBox", "QRadioButton", "QGroupBox", "QToolButton", "QAction"}
# method calls whose first string argument is a mnemonic-parsing label
_METHODS = {"addAction"}

# intended mnemonics / known-safe exceptions: (basename, lineno) — currently none
_ALLOW: set = set()


def _lone_amp(s: str) -> bool:
    return "&" in s.replace("&&", "")


def _offenders():
    bad = []
    for base, _dirs, files in os.walk(WYRM):
        if "__pycache__" in base or os.sep + "bin" in base:
            continue
        for fn in files:
            if not fn.endswith(".py"):
                continue
            path = os.path.join(base, fn)
            try:
                tree = ast.parse(open(path, encoding="utf-8").read())
            except (OSError, SyntaxError):
                continue
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call) or not node.args:
                    continue
                name = None
                if isinstance(node.func, ast.Name):
                    name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    name = node.func.attr
                if name not in _WIDGETS and name not in _METHODS:
                    continue
                a0 = node.args[0]
                if isinstance(a0, ast.Constant) and isinstance(a0.value, str) and _lone_amp(a0.value):
                    if (fn, node.lineno) in _ALLOW:
                        continue
                    bad.append(f"{os.path.relpath(path, ROOT)}:{node.lineno}  {name}({a0.value!r})")
    return bad


def test_no_unescaped_ampersand_in_widget_labels():
    bad = _offenders()
    assert not bad, "literal '&' (use '&&') in widget labels:\n" + "\n".join(bad)


if __name__ == "__main__":
    import traceback
    try:
        test_no_unescaped_ampersand_in_widget_labels()
        print("PASS test_no_unescaped_ampersand_in_widget_labels")
    except AssertionError:
        print("FAIL"); traceback.print_exc(); sys.exit(1)
