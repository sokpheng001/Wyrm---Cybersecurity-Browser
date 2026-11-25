#!/usr/bin/env bash
#------------------------------------------------------------------------------
# Wyrm — tools/macos_sign.sh
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
# Sign (and optionally notarize) the macOS app bundle — F3.
#
#   tools/macos_sign.sh sign     "dist/Wyrm Browser.app"
#   tools/macos_sign.sh notarize <file.zip|file.dmg|app>   # submits, waits, staples
#
# Environment (all optional — read from CI secrets, never hard-coded):
#   MACOS_SIGN_IDENTITY   "Developer ID Application: Name (TEAMID)". Unset -> ad-hoc signature ("-"), which
#                         Gatekeeper rejects for downloaded apps; this is logged loudly.
#   APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD   notarytool credentials (Apple ID + app-specific password),
#   or APPLE_API_KEY_PATH, APPLE_API_KEY_ID, APPLE_API_ISSUER   (App Store Connect API key).
#   No notary credentials -> notarization is skipped (logged).
#
# Every Mach-O file is signed individually, innermost first (PyInstaller bootloader, Python.framework, Qt
# frameworks, QtWebEngineProcess.app, pdtools binaries, Tor, …), then each nested bundle, then the app — with
# the hardened runtime and a secure timestamp. `codesign --deep` is not used: Apple deprecates it for signing
# and it skips loose Mach-O files that aren't in standard bundle locations.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ENT="${MACOS_ENTITLEMENTS:-$HERE/../installer/entitlements.plist}"
ID="${MACOS_SIGN_IDENTITY:-}"

log() { echo "[macos_sign] $*"; }
warn() { if [ -n "${GITHUB_ACTIONS:-}" ]; then echo "::warning::$*"; else echo "[macos_sign] WARNING: $*"; fi; }

sign_one() {   # $1 = path
  if [ -n "$ID" ]; then
    codesign --force --options runtime --timestamp --entitlements "$ENT" --sign "$ID" "$1"
  else
    codesign --force --options runtime --entitlements "$ENT" --sign - "$1"
  fi
}

depth_sorted() {   # stdin: paths -> deepest first
  awk -F/ '{print NF "\t" $0}' | sort -rn -k1,1 | cut -f2-
}

cmd_sign() {
  local app="$1"
  [ -d "$app" ] || { echo "no such app: $app" >&2; exit 2; }
  if [ -n "$ID" ]; then
    log "signing with Developer ID: $ID"
  else
    warn "MACOS_SIGN_IDENTITY is not set: using an AD-HOC signature. Gatekeeper will reject the downloaded app \
(spctl: rejected). Set the MACOS_CERT_P12 / MACOS_CERT_PASSWORD / MACOS_SIGN_IDENTITY secrets to sign for release."
  fi
  xattr -cr "$app"
  local n=0
  # 1) every Mach-O file (executables, dylibs, .so, framework binaries), deepest first
  while IFS= read -r f; do
    if file -b "$f" | grep -q "Mach-O"; then sign_one "$f"; n=$((n + 1)); fi
  done < <(find "$app/Contents" -type f \( -perm -u+x -o -name "*.dylib" -o -name "*.so" \) | depth_sorted)
  # 2) nested bundles (.framework, helper .app such as QtWebEngineProcess.app), deepest first
  while IFS= read -r b; do sign_one "$b"; n=$((n + 1)); done \
    < <(find "$app/Contents" -type d \( -name "*.framework" -o -name "*.app" \) | depth_sorted)
  # 3) the app itself
  sign_one "$app"
  log "signed $n nested items + the app"
  codesign --verify --deep --strict --verbose=2 "$app"
  codesign -dv "$app" 2>&1 | grep -E "^(Authority|TeamIdentifier|Signature|Runtime)" || true
}

cmd_notarize() {
  local target="$1" auth=()
  if [ -z "$ID" ]; then warn "not notarizing: the app is ad-hoc signed (no MACOS_SIGN_IDENTITY)"; return 0; fi
  if [ -n "${APPLE_API_KEY_PATH:-}" ] && [ -n "${APPLE_API_KEY_ID:-}" ] && [ -n "${APPLE_API_ISSUER:-}" ]; then
    auth=(--key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER")
  elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
    auth=(--apple-id "$APPLE_ID" --team-id "$APPLE_TEAM_ID" --password "$APPLE_APP_PASSWORD")
  else
    warn "not notarizing $target: no notary credentials (APPLE_ID/APPLE_TEAM_ID/APPLE_APP_PASSWORD or API key)"
    return 0
  fi
  local submit="$target"
  if [ -d "$target" ]; then   # an .app must be zipped for submission; the ticket is stapled to the .app
    submit="$(mktemp -d)/$(basename "$target").zip"
    ditto -c -k --keepParent "$target" "$submit"
  fi
  log "submitting $(basename "$submit") to Apple notary service (waits for the result)"
  local out; out="$(xcrun notarytool submit "$submit" "${auth[@]}" --wait --output-format json)" || true
  echo "$out"
  if ! echo "$out" | grep -q '"status" *: *"Accepted"'; then
    local sid; sid="$(echo "$out" | sed -n 's/.*"id" *: *"\([^"]*\)".*/\1/p' | head -1)"
    [ -n "$sid" ] && xcrun notarytool log "$sid" "${auth[@]}" || true
    echo "notarization failed" >&2; exit 1
  fi
  xcrun stapler staple "$target"
  xcrun stapler validate "$target"
  if [ -d "$target" ]; then spctl -a -vv "$target" || true; fi
}

case "${1:-}" in
  sign) cmd_sign "$2" ;;
  notarize) cmd_notarize "$2" ;;
  *) echo "usage: $0 sign <app> | notarize <app|dmg|zip>" >&2; exit 2 ;;
esac
