# PyInstaller spec - works on Windows, macOS and Linux (build on each OS; no cross-compiling).
#   pyinstaller --noconfirm wyrm.spec
import sys

VERSION = "1.0.0"

a = Analysis(
    ["run.py"],
    pathex=["."],
    datas=[("wyrm/citesee.js", "wyrm"), ("wyrm/youtube.js", "wyrm"), ("wyrm/fingerprint.js", "wyrm"),
           ("wyrm/security/pageinfo.js", "wyrm/security"),
           ("wyrm/assets", "wyrm/assets")],
    hiddenimports=["PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtSvg", "PySide6.QtNetwork", "adblock", "stem", "stem.process", "stem.control", "socks"],
    # trim Qt modules we never use (keeps the bundle smaller)
    excludes=["PySide6.Qt3DCore", "PySide6.QtQuick3D", "PySide6.QtCharts", "PySide6.QtDataVisualization",
              "PySide6.QtMultimedia", "PySide6.QtBluetooth", "PySide6.QtSensors", "PySide6.QtSerialPort",
              "PySide6.QtDesigner", "tkinter", "numpy", "matplotlib", "scipy", "pennylane", "qiskit"],
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,           # one-folder build: QtWebEngine needs its helper process + resources on disk
    name="Wyrm",
    console=False,                   # GUI app, no terminal window
    upx=False,
    icon="wyrm/assets/icon.ico" if sys.platform == "win32" else None,
    version="installer/version_info.txt" if sys.platform == "win32" else None,
)
coll = COLLECT(exe, a.binaries, a.datas, name="Wyrm", upx=False)

if sys.platform == "darwin":
    app = BUNDLE(coll, name="Wyrm.app", icon="wyrm/assets/icon.icns",
                 bundle_identifier="com.hackpi.wyrm",
                 info_plist={"CFBundleDisplayName": "Wyrm", "CFBundleShortVersionString": VERSION,
                             "NSHighResolutionCapable": True})

