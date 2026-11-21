#------------------------------------------------------------------------------
# Wyrm — run.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""Launch Wyrm (powered by HackPi).

    python run.py [url-or-query]      normal window
    python run.py --tor               private window over the Tor network
"""
import os
import sys
from pathlib import Path

from PySide6.QtCore import QCoreApplication, QSettings, QStandardPaths, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import QApplication, QDialog, QLabel, QProgressBar, QPushButton, QVBoxLayout

from wyrm.scheme import register_scheme

HERE = Path(getattr(sys, "_MEIPASS", Path(__file__).parent))


def apply_proxy_flags():
    """Chromium reads proxy settings at startup, so they're passed as engine flags."""
    s = QSettings()
    if not s.value("proxy/enabled", False, type=bool):
        return
    flags = [f"--proxy-server=http://{s.value('proxy/host', '127.0.0.1')}:{s.value('proxy/port', 8080, type=int)}",
             "--proxy-bypass-list=<-loopback>"]
    if s.value("proxy/insecure", True, type=bool):
        flags.append("--ignore-certificate-errors")
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "") + " " + " ".join(flags)).strip()


class TorStarter(QThread):
    progress = Signal(int, str)
    failed = Signal(str)

    def __init__(self, tor, port):
        super().__init__()
        self.tor, self.port = tor, port

    def run(self):
        try:
            self.tor.start(self.port, lambda p, m: self.progress.emit(p, m))
        except Exception as e:  # noqa: BLE001
            self.failed.emit(str(e))


class TorDialog(QDialog):
    """Connection screen shown while Tor bootstraps (like Brave's 'Connecting to Tor')."""

    def __init__(self, tor, port):
        super().__init__()
        self.setWindowTitle("Connecting to Tor")
        self.resize(560, 320)
        self.setMinimumSize(420, 240)
        self.setSizeGripEnabled(True)   # resizable so long messages can be read in full
        self.setWindowFlag(Qt.WindowType.WindowMaximizeButtonHint, True)
        v = QVBoxLayout(self)
        v.setContentsMargins(24, 24, 24, 24)
        title = QLabel("<span style='font-size:20px;font-weight:300'>Connecting to the Tor network</span>")
        v.addWidget(title)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        v.addWidget(self.bar)
        from PySide6.QtWidgets import QTextEdit
        self.msg = QTextEdit()          # read-only, scrollable, selectable — full error always visible
        self.msg.setReadOnly(True)
        self.msg.setPlainText("Starting…")
        v.addWidget(self.msg, 1)
        note = QLabel("<span style='color:gray;font-size:12px'>Traffic is routed through three Tor relays. Nothing from "
                      "this window is saved to disk. The first connection downloads Tor from torproject.org and verifies "
                      "its checksum.</span>")
        note.setWordWrap(True)
        v.addWidget(note)
        self.cancel = QPushButton("Cancel")
        self.cancel.clicked.connect(self.reject)
        v.addWidget(self.cancel, 0, Qt.AlignmentFlag.AlignRight)
        self.worker = TorStarter(tor, port)
        self.worker.progress.connect(self._progress)
        self.worker.failed.connect(self._failed)
        self.worker.finished.connect(lambda: self.bar.value() >= 100 and self.accept())
        self.worker.start()

    def _progress(self, p, m):
        self.bar.setValue(p)
        self.msg.setPlainText(m)

    def _failed(self, err):
        self.msg.setHtml(f"<span style='color:#da1e28'>Couldn't connect to Tor:</span><br><br>{err}")
        self.cancel.setText("Close")


def main():
    QCoreApplication.setOrganizationName("HackPi")
    QCoreApplication.setApplicationName("Wyrm")
    tor_mode = "--tor" in sys.argv
    argv = [a for a in sys.argv if a != "--tor"]
    tor = None
    if tor_mode:
        from wyrm.tor import TorManager, chromium_flags, free_port
        socks = free_port()
        # Chromium reads proxy/DNS flags from this env var (reliable; argv is not)
        os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
            os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "") + " " + " ".join(chromium_flags(socks))).strip()
        # the browser's own requests (search, analysis, recon) also go through Tor
        for var in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            os.environ[var] = f"socks5h://127.0.0.1:{socks}"
        os.environ["NO_PROXY"] = "127.0.0.1,localhost"
    else:
        apply_proxy_flags()
    register_scheme()  # must happen before QApplication exists
    app = QApplication(argv)
    app.setApplicationDisplayName("Wyrm Browser")  # shown name; data folder stays "Wyrm"
    app.setWindowIcon(QIcon(str(HERE / "wyrm" / "assets" / "icon.png")))
    if sys.platform == "win32":  # own taskbar group + icon instead of python.exe's
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("HackPi.Wyrm")

    from wyrm import engines, theme
    theme.load_fonts()          # IBM Plex Sans / Mono (SIL OFL), bundled
    app.setFont(theme.app_font())
    app.setStyle(theme.AppStyle())  # Fusion on every OS + hand cursor / visible scrollbar on dropdowns

    if tor_mode:
        data_dir = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation))
        tor = TorManager(data_dir)
        # the connect dialog follows the user's chosen theme (system/dark/light), not a forced dark
        from PySide6.QtGui import QGuiApplication
        from PySide6.QtCore import Qt as _Qt
        pref = QSettings().value("theme", "system")
        if pref not in ("dark", "light"):
            pref = "light" if QGuiApplication.styleHints().colorScheme() == _Qt.ColorScheme.Light else "dark"
        mode = QSettings().value("mode", "blue")
        app.setPalette(theme.palette(pref, mode))
        app.setStyleSheet(theme.stylesheet(pref, data_dir / "ui", mode))
        if TorDialog(tor, socks).exec() != QDialog.DialogCode.Accepted:
            tor.stop()
            sys.exit(0)
        app.aboutToQuit.connect(tor.stop)

    from wyrm.window import MainWindow
    win = MainWindow(tor=tor)
    rest = [a for a in argv[1:] if not a.startswith("--")]
    if rest:
        win.current_view().setUrl(QUrl(engines.resolve(" ".join(rest))))
    win.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
