#------------------------------------------------------------------------------
# Wyrm — wyrm.spec
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
# PyInstaller spec - works on Windows, macOS and Linux (build on each OS; no cross-compiling).
#   pyinstaller --noconfirm wyrm.spec
import re
import sys

# single source of truth: wyrm/__init__.py
VERSION = re.search(r'__version__\s*=\s*"([^"]+)"', open("wyrm/__init__.py", encoding="utf-8").read()).group(1)

# Windows file details (Properties > Details): fill the template with the current version and year range
VERSION_FILE = None
if sys.platform == "win32":
    import datetime, os
    nums = [int(x) for x in re.findall(r"\d+", VERSION)][:4]
    nums += [0] * (4 - len(nums))
    text = open("installer/version_info.txt", encoding="utf-8").read()
    text = (text.replace("{VT}", str(tuple(nums))).replace("{V4}", ".".join(map(str, nums)))
                .replace("{V}", VERSION).replace("{YEARS}", f"2023-{datetime.date.today().year}"))
    os.makedirs("build", exist_ok=True)
    VERSION_FILE = os.path.join("build", "version_info.txt")
    open(VERSION_FILE, "w", encoding="utf-8").write(text)

a = Analysis(
    ["run.py"],
    pathex=["."],
    datas=[("wyrm/citesee.js", "wyrm"), ("wyrm/youtube.js", "wyrm"), ("wyrm/fingerprint.js", "wyrm"),
           ("wyrm/security/pageinfo.js", "wyrm/security"),
           ("wyrm/assets", "wyrm/assets")],
    hiddenimports=["PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.QtSvg", "PySide6.QtNetwork", "adblock", "stem", "stem.process", "stem.control", "socks", "wyrm.security.triage", "wyrm.security.fuzzer", "wyrm.security.secsearch", "wyrm.security.rewrite"],
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
    version=VERSION_FILE,
)
coll = COLLECT(exe, a.binaries, a.datas, name="Wyrm", upx=False)

if sys.platform == "darwin":
    app = BUNDLE(coll, name="Wyrm.app", icon="wyrm/assets/icon.icns",
                 bundle_identifier="com.hackpi.wyrm",
                 info_plist={"CFBundleDisplayName": "Wyrm", "CFBundleShortVersionString": VERSION,
                             "CFBundleVersion": VERSION,
                             "LSMinimumSystemVersion": "12.0",
                             "NSHighResolutionCapable": True})

