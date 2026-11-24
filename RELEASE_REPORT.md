# Release Report — Wyrm Browser v0.5.0 security patch

Results for the **Pre-Release Fix Brief** (security addendum / release gate). One commit per task ID; all
commits verified free of any third-party attribution trailer. Verification was done on Windows 11 with the
bundled Python/PySide6; where a check needs the shipped build or signing infrastructure it is called out.

## Release gate

| ID | Status | Notes |
|----|--------|-------|
| SEC-1 | Partial (build task) | Engine version now shown in About; the actual Chromium upgrade is a rebuild task. |
| SEC-2 | Done (code) + release decision | Install dir ACLs locked down; defaulting to an elevated %ProgramFiles% install is a release decision. |
| SEC-3 | Done (prior commit `e3e2fda`) | Anti-fingerprinting no longer self-identifies; realistic per-session values; deterministic noise. |
| H-1 | Done (`84fd47a`) | Not-secure icon on cert errors. |
| H-2 | Done (`bea72a1`) | "Trust proxy CA / ignore cert errors" defaults OFF + red banner. |
| H-3 | Done (`a77233e`) | Ctrl+T bound on a single action. |
| H-4 / M-1 | Done (`495081c`) | Single-instance; New window in-process; crash log. |

## Browser — new security findings

### SEC-1 (High) — Outdated Chromium engine — PARTIAL
- **Done:** About now shows `Chromium <ver> · Qt WebEngine <ver>` (`qWebEngineChromiumVersion()`), so an
  outdated engine is visible to users/reviewers. Commit `b78e708`.
- **Still required (build task — cannot be done from app code):** rebuild against the latest stable
  PySide6/QtWebEngine (6.10.x LTS or newer) so the shipped `Qt6WebEngineCore.dll` carries the current Chromium
  security baseline (shipped build is `Chrome/140.0.7339.225`). Adopt a process to rebase within ~2 weeks of
  each upstream security release.
- **Accept when:** the shipped DLL's `Chrome/<ver>` matches a current QtWebEngine release, and About shows it.

### SEC-2 (High) — World-writable install — DONE (code) + release decision
- **Done:** `installer/windows.iss` now has a `[Dirs]` entry granting Administrators/SYSTEM Full and
  Users **Read & Execute only** on `{app}` (inherited by `_internal`). Closes DLL-planting / exe-replacement.
  Commit `85b7109`.
- **Release decision:** the ACL applies fully for an elevated all-users install. `PrivilegesRequired=lowest`
  is kept so no-admin install and **silent in-app updates** keep working (a per-user install lands under the
  user's own profile, which is already private). Defaulting to an elevated %ProgramFiles% install would protect
  every install but makes silent auto-update require elevation — decide before GA.
- **Accept when:** `icacls` on the install dir and `_internal` shows no Write/Modify for Users/Authenticated
  Users (holds for an elevated install with this ACL).

### SEC-3 (High) — DONE (prior commit `e3e2fda`).

### SEC-4 (Medium) — Forged Security/Traffic rows — DONE
- `capture.js` grabs the original `console.debug` at document start and emits a sentinel carrying a per-process
  random token (`secrets.token_hex`), so a page can neither read the token nor intercept emissions; the
  `window.__wyrmCap` global is gone; `_on_capture` ignores sentinels when capture is off. Panel fields already
  render as inert text (see SEC-6). Commit `3546f9f`.
- **Accept when:** a page printing `[[WYRMCAP]]…` cannot add rows, and fields render inert — met.

### SEC-5 (Medium) — Papers panel page-controlled text — DONE
- Paper link entries are plain `QListWidgetItem` text; the tooltip (page-controlled key/href) is now escaped
  (Qt auto-renders a tooltip as rich text otherwise); the current-paper card refuses remote resources
  (`_PaperCard.loadResource`) and already HTML-escapes every field. Commit `39ae666`.
- **Accept when:** a link whose text contains `<img onerror>` shows literal and loads nothing — met.

### SEC-6 (Medium) — Escape untrusted site data in all panels — DONE
- Audited Overview/Recon/Traffic/Site map/DOM/Capture rendering paths. Fixes: escape the CVE link URL in
  Overview; escape site-map/recon tooltips (the remaining rich-text injection vector). Verified already-safe
  paths (plain table/tree/list widgets; `setPlainText` capture view; escaped issue cards and HTML/MD report).
  No CSV/spreadsheet export exists, so there is no formula-injection surface (HAR is JSON, sitemap export is a
  URL .txt). Commit `f6708c9`.
- **Accept when:** a target serving markup in title/headers/security.txt shows inert text, and exports are
  formula-safe — met.

### SEC-7 (Medium) — API key in plaintext — DONE
- New `wyrm/secretstore.py` encrypts secrets with Windows DPAPI (per-user) in a tagged `enc:v1:` format;
  Settings load/save the key through it; a startup migration re-stores any existing plaintext key as ciphertext.
  Non-Windows falls back to storing as-is (no OS keystore wired yet). Commit `7b664e1`.
- **Accept when:** the registry value is ciphertext — met on Windows (verified: round-trip + "ciphertext does
  not contain the raw key").

### SEC-8 (Medium) — MITM CA key on disk + crash-safe lifecycle — DONE
- CA private key is DPAPI-protected at rest with user-only file/dir ACLs; CA lifetime cut to 90 days and a fresh
  CA is regenerated per session; at startup, when the proxy is OFF the trusted CA is removed and the on-disk
  cert/key wiped (crash-safe), and when ON any stale CA is dropped before trusting the fresh one. Commit `d2e6168`.
- **Accept when:** the key isn't a usable world-readable file, and a crash-with-proxy-on leaves no trusted Wyrm
  CA after the next launch (with the proxy off) — met (verified: key file is DPAPI ciphertext, not PEM).

### SEC-9 (Low–Med) — Updater authenticity — DONE (code) + build task
- Checksum is now **mandatory** — an update with no published checksum is refused (no silent fallback).
  `verify_authenticode` rejects a present-but-tampered signature (HashMismatch/NotTrusted); `REQUIRE_SIGNATURE`
  + `EXPECTED_PUBLISHER` let the release require a signature once the installer is code-signed. Commit `214f293`.
- **Build task:** obtain a code-signing certificate, Authenticode-sign the installer, set `REQUIRE_SIGNATURE=True`.
- **Accept when:** a checksum-less installer is refused (met) and an unsigned/forged one is refused (met for
  forged; met for unsigned once signing is enabled).

### SEC-10 (Low) — `wyrm://` privileged scheme — DONE
- New `wyrm/navpolicy.py` + `acceptNavigationRequest` block page-initiated navigation to `wyrm://`, `file://`,
  `javascript:` and top-level `data:` (user-driven and own-chrome navigations still allowed); `wyrm://history`
  additionally checks the initiator. Regression tests in `tests/test_navpolicy.py` (4/4 pass). Commit `4121acf`.
- **Accept when:** a web page can't reach `wyrm://history` — met.

### BUG-1 (Medium) — Recon host:port/IP parse — DONE
- `use_current` acts only on http(s) views via `QUrl.host()` (never fills "home" from `wyrm://home`);
  `_host_from_text` reduces a typed URL/`host:port` to the bare host; crt.sh is skipped for IPs/localhost with
  an explanation. Commit `8cda307`. Verified with a parse table.
- **Accept when:** "Use current" on `http://127.0.0.1:8777/` yields `127.0.0.1` — met.

### BUG-2 (Medium) — Invalid default Triage model — DONE
- `DEFAULT_MODEL` is now a real current Claude id (`claude-sonnet-5-5`); the placeholder is removed everywhere
  and Tools falls back to it. Commit `8818fb0`.
- **Accept when:** Triage works with only a valid API key entered — met (default is valid; user can override).

### UX-1 (Medium) — Panel close / floating Ctrl+W — DONE
- The toolbar Shields button is a true toggle (opens Shields / closes the panel); every closable dock gets a
  Ctrl+W shortcut so a floating panel closes with Ctrl+W. The docked and floating panels already have a clear ×
  and a dock/float button. Commit `6dd993b`.

### Confirmed-safe regression items (kept as tests / behaviour)
- Malicious `document.title`, typed `javascript:`→search, Shields-0-on-localhost: unchanged and still safe.
- Page-initiated `file://`/`data:`/`javascript:`/`wyrm://` navigation is now blocked (SEC-10) with an automated
  test (`tests/test_navpolicy.py`).

## Website items — OUT OF SCOPE (server-side, not this repo)
LRN-1, LRN-2, LRN-3 (learn.bykh.org) and WEB-1, WEB-2, WEB-3 (bykh.org) are server-side and live outside this
repository. Not addressed here; forward to the site maintainers.

## Final checklist status
- [x] Engine version shown in About (SEC-1); engine upgrade = build task
- [x] Install-dir ACLs: no Write/Modify for Users on an elevated install (SEC-2)
- [x] No readable `window.__wyrm*`; realistic FP; stable canvas within session (SEC-3)
- [x] Forged `[[WYRMCAP]]` rows don't appear; panel fields inert (SEC-4/5/6)
- [x] "Use current" on an IP:port parses the host, not "home" (BUG-1)
- [x] One control closes the docked panel; floating closes with Ctrl+W (UX-1)
- [x] H-1…H-4 done (prior commits)
- [x] Page-initiated file/data/javascript/wyrm navigation blocked + automated test (SEC-10)
- [ ] learn.bykh.org counter endpoints rate-limited (LRN-1) — server-side, out of scope
- [x] API key encrypted at rest (SEC-7)
- [x] MITM CA key protected + removed on startup when proxy off (SEC-8)
- [x] Updater requires a checksum / rejects tampered installers (SEC-9); signing = build task
- [x] `wyrm://history` not reachable from a web page (SEC-10)
- [x] AI Triage works with a valid default model (BUG-2)

## Follow-ups not fixable in application code
1. **SEC-1** — rebuild against current QtWebEngine/Chromium.
2. **SEC-2** — decide elevated-%ProgramFiles% default vs silent per-user updates.
3. **SEC-9** — code-sign the installer and set `REQUIRE_SIGNATURE=True`.
