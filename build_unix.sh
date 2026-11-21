#!/usr/bin/env bash
# Build The Hidden Browser on macOS or Linux.
#   macOS -> dist/Wyrm.app + dist/Wyrm-macos-<arm64|intel>.dmg (drag-to-Applications installer)
#            built for the CPU of the Mac/runner it runs on (Apple Silicon -> arm64, Intel -> intel)
#   Linux -> dist/Wyrm-linux.tar.gz (contains install.sh: adds a menu entry + icon for the user)
set -euo pipefail
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/python -m pip install -q -r requirements.txt pyinstaller pillow
QT_QPA_PLATFORM=offscreen .venv/bin/python tools/make_icons.py
.venv/bin/python tools/fetch_filters.py
.venv/bin/python -m PyInstaller --noconfirm --clean wyrm.spec

if [ "$(uname -s)" = "Darwin" ]; then
  # Re-seal the bundle with a consistent ad-hoc signature (no Apple Developer ID here). A broken or
  # partial signature is what makes macOS report a downloaded app as "damaged".
  xattr -cr dist/Wyrm.app
  codesign --force --deep --sign - dist/Wyrm.app
  codesign --verify --deep --strict dist/Wyrm.app
  case "$(uname -m)" in arm64) ARCH=arm64 ;; *) ARCH=intel ;; esac
  rm -rf dist/dmg && mkdir -p dist/dmg
  cp -R dist/Wyrm.app dist/dmg/
  ln -s /Applications dist/dmg/Applications
  hdiutil create -volname "The Hidden Browser" -srcfolder dist/dmg -ov -format UDZO "dist/Wyrm-macos-$ARCH.dmg"
else
  cp installer/hiddenbrowser.desktop dist/Wyrm/
  cp wyrm/assets/icon.png dist/Wyrm/hiddenbrowser.png
  cat > dist/Wyrm/install.sh <<'EOF'
#!/usr/bin/env bash
# Installs The Hidden Browser for the current user (~/.local), no root needed.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.local/opt/hiddenbrowser"
mkdir -p "$DEST" "$HOME/.local/bin" "$HOME/.local/share/applications" "$HOME/.local/share/icons/hicolor/512x512/apps"
cp -R "$SRC/." "$DEST/"
ln -sf "$DEST/Wyrm" "$HOME/.local/bin/Wyrm"
cp "$SRC/hiddenbrowser.png" "$HOME/.local/share/icons/hicolor/512x512/apps/hiddenbrowser.png"
sed "s|Exec=Wyrm|Exec=$DEST/Wyrm|" "$SRC/hiddenbrowser.desktop" > "$HOME/.local/share/applications/hiddenbrowser.desktop"
echo "Installed. Launch 'The Hidden Browser' from your app menu, or run: Wyrm"
EOF
  chmod +x dist/Wyrm/install.sh
  tar -czf dist/Wyrm-linux.tar.gz -C dist Wyrm
fi
echo "Done. See dist/"
