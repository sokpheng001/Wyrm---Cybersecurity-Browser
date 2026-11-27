#------------------------------------------------------------------------------
# Wyrm — run.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
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
    from wyrm import proxycfg   # B7: per-engagement choice (Chromium's flags are fixed for this run)
    if proxycfg.upstream_unverified(s, proxycfg.startup_engagement(s)):
        flags.append("--ignore-certificate-errors")
    os.environ["WYRM_TLS_UNVERIFIED_AT_START"] = "1" if proxycfg.upstream_unverified(
        s, proxycfg.startup_engagement(s)) else "0"
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


def _migrate_secrets():
    """Move any secret still kept in QSettings (plain text, or DPAPI on Windows) into the OS keyring (F4) and
    delete it from QSettings. Safe to run every launch."""
    try:
        from wyrm import secretstore
        secretstore.migrate(QSettings())   # F4: plain/DPAPI copies in QSettings -> OS keyring, then deleted
    except Exception:  # noqa: BLE001 — migration must never block startup
        pass


def _apply_base_engine_flags():
    """Engine flags that apply to every window: smoother scrolling and compositing. Chromium reads these from
    QTWEBENGINE_CHROMIUM_FLAGS at startup (before QApplication exists)."""
    base = ["--enable-smooth-scrolling",
            "--enable-features=SmoothScrolling,OverlayScrollbar",
            "--disable-features=TouchpadOverscrollHistoryNavigation"]
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
        os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "") + " " + " ".join(base)).strip()


def main():
    QCoreApplication.setOrganizationName("HackPi")
    QCoreApplication.setApplicationName("Wyrm")
    _apply_base_engine_flags()
    _migrate_secrets()
    try:   # crash logging: Python-level faults go to a log with the Wyrm version (H-4)
        import faulthandler
        from wyrm import __version__ as _wv
        _ld = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation))
        _ld.mkdir(parents=True, exist_ok=True)
        _crash = open(_ld / "crash.log", "a", buffering=1, encoding="utf-8")
        import datetime as _dt
        _crash.write(f"\n=== Wyrm {_wv} started {_dt.datetime.now():%Y-%m-%d %H:%M:%S} ===\n")
        faulthandler.enable(_crash)
    except Exception:  # noqa: BLE001 — logging must never block startup
        pass
    tor_mode = "--tor" in sys.argv
    private_mode = "--private" in sys.argv and not tor_mode  # private window: nothing is saved
    argv = [a for a in sys.argv if a not in ("--tor", "--private")]
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
        if not private_mode:  # built-in intercepting proxy (HTTPS capture), if enabled
            from wyrm.security import mitm
            _dd = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppDataLocation))
            mflags = mitm.start_if_enabled(_dd)
            if mflags:
                os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = (
                    os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "") + " " + " ".join(mflags)).strip()
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

    rest = [a for a in argv[1:] if not a.startswith("--")]
    # Single instance for normal windows: a second launch hands its URL to the running app and exits, so the
    # on-disk Chromium profile is never opened by two processes at once (that crashes Qt WebEngine). Tor/private
    # windows are intentionally separate processes — each uses its own or an off-the-record profile.
    single_server = None
    if not tor_mode and not private_mode:
        from PySide6.QtNetwork import QLocalServer, QLocalSocket
        key = "WyrmBrowser-instance"
        probe = QLocalSocket()
        probe.connectToServer(key)
        if probe.waitForConnected(300):
            probe.write((" ".join(rest)).encode())
            probe.flush()
            probe.waitForBytesWritten(500)
            probe.disconnectFromServer()
            sys.exit(0)   # another Wyrm is already running — it will open our URL / a new window
        QLocalServer.removeServer(key)   # clear any stale socket from a crash
        single_server = QLocalServer()
        single_server.listen(key)

    from wyrm.window import MainWindow
    win = MainWindow(tor=tor, private=private_mode)
    if rest:
        win.current_view().setUrl(QUrl(engines.resolve(" ".join(rest))))
    win.show()
    if single_server is not None:
        def _on_second_launch():
            conn = single_server.nextPendingConnection()
            if conn is None:
                return
            conn.waitForReadyRead(400)
            url = bytes(conn.readAll()).decode(errors="ignore").strip()
            nw = win.open_new_window()
            if url and nw is not None:
                nw.current_view().setUrl(QUrl(engines.resolve(url)))
        single_server.newConnection.connect(_on_second_launch)
        app._wyrm_single_server = single_server   # keep a reference for the app's lifetime
    app.aboutToQuit.connect(_before_quit)
    code = app.exec()
    _after_qt(app)
    os._exit(code)   # B4: Qt is torn down; skip Py_FinalizeEx, which destroyed leftover Qt objects out of order


def _before_quit():
    """B4: stop every timer and background worker while Qt is still fully alive."""
    from PySide6.QtCore import QTimer
    for w in QApplication.topLevelWidgets():
        try:
            for t in w.findChildren(QTimer):
                t.stop()
            runner = getattr(w, "runner", None)
            if runner is not None:
                runner.shutdown()
        except RuntimeError:   # already deleted on the C++ side
            pass


def _after_qt(app):
    """B4: release Python references to Qt objects in an orderly way before the process exits. A QPainter (or any
    Qt object) kept alive by a stored exception/traceback used to be destroyed during Python's own shutdown —
    after Qt — and crashed in QPainter::end(). Settings are flushed; nothing else needs Python's finalizer."""
    import gc
    from PySide6.QtCore import QCoreApplication, QEvent, QSettings
    for attr in ("last_type", "last_value", "last_traceback", "last_exc"):
        if hasattr(sys, attr):
            try:
                setattr(sys, attr, None)
            except Exception:  # noqa: BLE001
                pass
    try:
        QSettings().sync()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        QCoreApplication.processEvents()
    except Exception:  # noqa: BLE001
        pass
    gc.collect()
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass


if __name__ == "__main__":
    main()
