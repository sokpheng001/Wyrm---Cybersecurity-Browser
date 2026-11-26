#------------------------------------------------------------------------------
# Wyrm — tests/test_ui_nav.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""QA-U1: at its minimum width the toolbar must not overlap — low-priority widgets collapse into an overflow
menu instead. Building a full QtWebEngine MainWindow has to happen in its own process (it doesn't share cleanly
with the rest of the suite), so the pytest test runs the checks below in a subprocess and asserts success."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_nav_overlap_and_overflow():
    env = {**os.environ, "QT_QPA_PLATFORM": "offscreen", "PYTHONIOENCODING": "utf-8"}
    r = subprocess.run([sys.executable, os.path.abspath(__file__), "--run"],
                       capture_output=True, text=True, timeout=180, env=env)
    assert r.returncode == 0, "QA-U1 checks failed:\n" + (r.stdout or "") + "\n" + (r.stderr or "")[-2000:]


def _run_checks():
    from PySide6.QtCore import QCoreApplication
    from PySide6.QtWidgets import QApplication
    QCoreApplication.setOrganizationName("HackPi")
    QCoreApplication.setApplicationName("Wyrm")
    from wyrm.scheme import register_scheme
    register_scheme()
    app = QApplication.instance() or QApplication([])
    from wyrm.mainwindow.window import MainWindow

    w = MainWindow()
    w.show()
    app.processEvents()

    # 1) at minimum width, no two visible nav children overlap
    w.resize(w.minimumWidth(), 720)
    for _ in range(4):
        app.processEvents()
    nav = w.nav
    kids = [c for c in nav.children()
            if hasattr(c, "isVisible") and c.isVisible() and hasattr(c, "geometry")
            and c.width() > 1 and c.height() > 1]
    boxes = [(c.objectName() or type(c).__name__, c.geometry()) for c in kids]
    for i in range(len(boxes)):
        for j in range(i + 1, len(boxes)):
            inter = boxes[i][1].intersected(boxes[j][1])
            assert not (inter.width() > 2 and inter.height() > 2), \
                f"overlap at min width {w.minimumWidth()}: {boxes[i][0]} & {boxes[j][0]}"
    assert w.b_overflow.isVisible(), "overflow button should show at minimum width"

    # 2) when wide, everything is shown and the overflow is hidden
    w.resize(1500, 720)
    for _ in range(4):
        app.processEvents()
    assert w.engine_box.isVisible() and not w.b_overflow.isVisible()
    print("QA-U1 OK")

    # 3) Security panel tool nav: search finds nested tools, groups collapse, pins go to the top
    p = w.security
    p._settings = None            # don't write pins / collapsed groups into the real user settings
    p._pinned, p._collapsed = [], set()
    p._render_nav()
    p.show_tab("Shields")
    app.processEvents()
    p.nav_search.setText("repeater")
    app.processEvents()
    assert p._result_entries and p._result_entries[0]["sub"] == "Repeater", p._result_entries
    p._open_first_result()
    app.processEvents()
    assert p.current_page() is p.tools_tab and p.tools_tab.current_tool() == "Repeater"
    assert p.tools_tab._chips["Repeater"].isChecked()
    assert p.nav_search.text() == "", "opening a result clears the search"
    p._toggle_group("SCANNING")
    assert not p._nav_buttons["Audit"][0].isVisibleTo(p)
    p.show_tab("Audit")           # selecting a tool inside a collapsed group expands it
    app.processEvents()
    assert "SCANNING" not in p._collapsed and p._nav_buttons["Audit"][0].isChecked()
    p.set_pinned("Intruder", True)
    app.processEvents()
    assert p._nb.itemAt(0).widget() is p._captions["PINNED"]
    assert p._nb.itemAt(1).widget() is p._nav_buttons["Intruder"][0]
    p.set_pinned("Intruder", False)
    assert "PINNED" not in [t for t, _n, _f in __import__("wyrm.panels.toolnav", fromlist=["x"]).sections(
        p._groups, p._pinned, p._collapsed)]
    print("Tool nav OK")

    # 4) hard reload (Ctrl+Shift+R) is wired and bound to exactly one window action
    from PySide6.QtGui import QKeySequence
    seqs = [QKeySequence("Ctrl+Shift+R"), QKeySequence("Ctrl+F5")]
    bound = [a for a in w.actions() if any(a.shortcuts() and s in a.shortcuts() for s in seqs)]
    assert bound, "Ctrl+Shift+R / Ctrl+F5 not bound to any window action"
    w._hard_reload()                 # must not raise with a live view
    w._hard_reload_view(w.current_view())
    print("Hard reload OK")


if __name__ == "__main__":
    if "--run" in sys.argv:
        _run_checks()
    else:
        test_nav_overlap_and_overflow()
        print("PASS test_nav_overlap_and_overflow")
