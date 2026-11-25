#!/usr/bin/env bash
#------------------------------------------------------------------------------
# Wyrm — build_unix.sh
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
# Build Wyrm Browser on macOS or Linux.
#   macOS -> "dist/Wyrm Browser.app" + dist/Wyrm-macos-<arm64|intel>.dmg (drag-to-Applications installer)
#            built for the CPU of the Mac/runner it runs on (Apple Silicon -> arm64, Intel -> intel)
#   Linux -> dist/Wyrm-linux.tar.gz (contains install.sh: adds a menu entry + icon for the user)
set -euo pipefail
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
.venv/bin/python -m pip install -q -r requirements.txt pyinstaller pillow
QT_QPA_PLATFORM=offscreen .venv/bin/python tools/make_icons.py
.venv/bin/python tools/fetch_filters.py
.venv/bin/python tools/fetch_pdtools.py   # bundle the ProjectDiscovery tools
# QA-H1: stamp the exact build (git short SHA + timestamp) so a tester can tell which build they have
printf 'SHA = "%s"\nBUILD_TIME = "%s"\n' "$(git rev-parse --short HEAD 2>/dev/null || echo '')" "$(date '+%Y-%m-%d %H:%M')" > wyrm/_buildinfo.py
.venv/bin/python -m PyInstaller --noconfirm --clean wyrm.spec

if [ "$(uname -s)" = "Darwin" ]; then
  # F3: sign every Mach-O inside-out with the hardened runtime (Developer ID when MACOS_SIGN_IDENTITY is set,
  # otherwise a clearly logged ad-hoc signature), then notarize + staple the app when notary credentials exist.
  APP="dist/Wyrm Browser.app"
  tools/macos_sign.sh sign "$APP"
  tools/macos_sign.sh notarize "$APP"
  case "$(uname -m)" in arm64) ARCH=arm64 ;; *) ARCH=intel ;; esac
  rm -rf dist/dmg && mkdir -p dist/dmg
  cp -R "$APP" dist/dmg/
  ln -s /Applications dist/dmg/Applications
  # ULMO = LZMA (macOS 10.15+), much smaller than UDZO. hdiutil sometimes fails with "Resource busy" on CI Macs
  # (a background scanner holding the files), so retry a few times before giving up.
  for attempt in 1 2 3; do
    hdiutil create -volname "Wyrm Browser" -srcfolder dist/dmg -ov -format ULMO "dist/Wyrm-macos-$ARCH.dmg" && break
    [ "$attempt" = 3 ] && exit 1
    echo "hdiutil failed (attempt $attempt), retrying in 20s..."; sleep 20
  done
  if [ -n "${MACOS_SIGN_IDENTITY:-}" ]; then   # sign + notarize + staple the disk image too
    codesign --force --timestamp --sign "$MACOS_SIGN_IDENTITY" "dist/Wyrm-macos-$ARCH.dmg"
    tools/macos_sign.sh notarize "dist/Wyrm-macos-$ARCH.dmg"
  fi
else
  cp installer/wyrm.desktop dist/Wyrm/
  cp wyrm/assets/icon.png dist/Wyrm/wyrm.png
  cat > dist/Wyrm/install.sh <<'EOF'
#!/usr/bin/env bash
# Installs Wyrm Browser for the current user (~/.local), no root needed.
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DEST="$HOME/.local/opt/wyrm"
# remove an install from before the rename (was "The Hidden Browser") so the menu has one entry
rm -rf "$HOME/.local/opt/hiddenbrowser" "$HOME/.local/share/applications/hiddenbrowser.desktop" \
       "$HOME/.local/share/icons/hicolor/512x512/apps/hiddenbrowser.png"
mkdir -p "$DEST" "$HOME/.local/bin" "$HOME/.local/share/applications" "$HOME/.local/share/icons/hicolor/512x512/apps"
cp -R "$SRC/." "$DEST/"
ln -sf "$DEST/Wyrm" "$HOME/.local/bin/Wyrm"
cp "$SRC/wyrm.png" "$HOME/.local/share/icons/hicolor/512x512/apps/wyrm.png"
sed "s|Exec=Wyrm|Exec=$DEST/Wyrm|" "$SRC/wyrm.desktop" > "$HOME/.local/share/applications/wyrm.desktop"
echo "Installed. Launch 'Wyrm Browser' from your app menu, or run: Wyrm"
EOF
  chmod +x dist/Wyrm/install.sh
  tar -czf dist/Wyrm-linux.tar.gz -C dist Wyrm
fi
echo "Done. See dist/"
