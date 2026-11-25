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


if __name__ == "__main__":
    if "--run" in sys.argv:
        _run_checks()
    else:
        test_nav_overlap_and_overflow()
        print("PASS test_nav_overlap_and_overflow")
