# Fix Report — Wyrm Browser v0.5.0 (WYRM_FIX_BRIEF)

Results for the 21-item UX/functional brief (H-1…L-10). One commit per task ID; all commits verified free of
any third-party attribution trailer. The security addendum is tracked separately in `RELEASE_REPORT.md`.

## HIGH

| ID | Status | Commit | Summary |
|----|--------|--------|---------|
| H-1 | Done | `84fd47a` | Not-secure icon on certificate-error pages (per-tab TLS state, cleared on navigation). |
| H-2 | Done | `bea72a1` | "Trust proxy CA / ignore cert errors" defaults OFF; persistent red banner when ignoring. |
| H-3 | Done | `a77233e` | Ctrl+T bound on a single shared New-tab action; debug duplicate-shortcut check. |
| H-4 | Done | `495081c` | Single-instance (QLocalServer); New window opens in-process on the shared profile; crash log. |

## MEDIUM

| ID | Status | Commit | Summary |
|----|--------|--------|---------|
| M-1 | Done | `495081c` | New window no longer spawns a second process on one profile (with H-4). |
| M-2 | Done | `ca4e9be` | Honour "Reopen last session's tabs"; only save/restore the session when on. |
| M-3 | Done | `9d42612` | Hide the address-bar suggestion dropdown on navigate and on load start. |
| M-4 | Done | `1fe3075` | Accessible names for toolbar buttons, address bar and combo boxes. |
| M-5 | Done | `a11b993` | With "Resist fingerprinting" on, strip the QtWebEngine token from the User-Agent; apply/restore on toggle. |
| M-6 | Done | `c656fe1` | Reset the per-tab Shields blocked counter on every navigation (any scheme). |
| M-7 | Done | `d2ba0eb` | Opening the Intercept window no longer turns interception on; raise it only when a request is held. |

## LOW

| ID | Status | Commit | Summary |
|----|--------|--------|---------|
| L-1 | Done | `ebbb11e` | Escaped `&&` in "Block malware & phishing sites". |
| L-2 | Done | `ebbb11e` | Removed the leftover "Developers:" credit and the prefilled placeholder AI model. |
| L-3 | **Skipped** | — | See below. |
| L-4 | Done (already satisfied) | — | Zoom shortcuts Ctrl++ / Ctrl+- / Ctrl+0 are bound in the keyboard-shortcut loop. |
| L-5 | Done | `1580e37` | "No engagement (Personal)" in italics; add-finding offers a "Create engagement…" button. |
| L-6 | Done | `ee2cafc` | Tooltips explain why "Add to findings" / "Look up CVEs" are disabled. |
| L-7 | Done | `0f2d5b2` | Recon list tooltips carry the full line so clipped security.txt/URLs stay readable; Traffic cells already expose the full URL; labels wrap and docks have minimum widths. |
| L-8 | Done | `876682d` | A lone DOM sink (no source in the same script) is reported as low, not high. |
| L-9 | Done | `6d6241b` | Bookmark star in the URL bar (filled when bookmarked) with an add/edit popover; Ctrl+D opens it. |
| L-10 | Done | `5691c5c` | Settings already use a consistent per-row layout; Port spinbox now has larger +/- step buttons. |

## Skipped (with reason)

- **L-3 (menu shortcut alignment).** Menu items show their shortcut in the label text (e.g. "History  Ctrl+H")
  while a few use the right-hand column. The accelerators are already bound globally via the keyboard-shortcut
  loop, so calling `QAction.setShortcut()` on the same menu actions would create *ambiguous shortcut*
  activations (the exact class of bug H-3 fixed). Making it consistent safely means making each menu action the
  single owner of its shortcut and removing the duplicate global binding — a broader refactor with real
  regression risk, not worth taking immediately before a release. Recommended as a follow-up tracked with H-3.

## Out of scope (per the brief)
Shields filter lists, nuclei templates, active-scanner logic, visual theme/branding, and website-side notes
were left unchanged.
