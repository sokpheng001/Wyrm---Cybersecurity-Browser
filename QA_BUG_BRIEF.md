# QA Bug Brief — Security panel (Wyrm v0.5.0) · 2026-11-25

**For: an AI coding agent.** Fix each item below as its own commit, using the ID as the commit-message prefix
(e.g. `fix(recon): QA-H2 keep scheme and port in well-known lookup`). Follow the format of `FIX_REPORT.md`:
when you are done, add a results table (ID · Status · Commit · Summary) to the end of this file.

## How this was tested

- **App under test:** the installed `D:\Program File\Wyrm Browser\Wyrm.exe`, driven by real mouse and keyboard
  input in Red Team mode, with an engagement `QA local test` scoped to `127.0.0.1`.
- **Target:** a deliberately vulnerable local site on `http://127.0.0.1:8765/`, checked in as
  `tests/fixtures/vulnlab.py` (see *Appendix A*). Use it for the regression tests below.
- **Every item was checked against the current source on `main`** (headless Python using the project's own
  modules), so each one is a real bug in today's code, not just in the stale build — unless it says otherwise.
- **Out of scope:** the Port scan was not run.

## Ground rules for the fixing agent

1. Only touch the files named in each item unless the fix genuinely needs more; say so in the commit body.
2. Add or extend a test in `tests/` for every item marked **Test required**. Run `pytest -q` before each commit.
3. Do not weaken any scope or authorization check. Several items *add* checks.
4. Keep the UI copy short and consistent with the existing panels.

---

## HIGH

### QA-H1 · Release/build process: the installed app is ~11 hours behind `main`, and both report "0.5.0"
**Evidence:** `Wyrm.exe` LastWriteTime is `2026-11-25 11:17`, but these commits landed after it:
`9ed90ef` metadata-SSRF, `d1d5c08` PAN/JWT/mixed-content/CSRF, `f9c80a5` debugger pages, `a5197eb` request
budget, and later ones. Audit → **Crawl + scan** on the fixture found **13** issues in the installed app.
The same crawl through current source (`spider.crawl` + `engine.scan_site`) finds **20**. Missing from the app:
AWS key exposed, unsigned JWT (`alg:none`), CORS, missing anti-CSRF token, Werkzeug debugger, blind boolean SQLi.
Both builds show version `0.5.0`, and a local build shows `(dev)` because `__build__ = 0`. A tester cannot tell which build they have.

**Fix:**
- In `wyrm/__init__.py` / `build_windows.ps1` / `wyrm.spec`, embed the **git short SHA and build timestamp**
  at build time (e.g. write `wyrm/_buildinfo.py` from the build script). Show it in *About* and in
  `version_label()`, e.g. `0.5.0 (build 0, 4cc1acd, 2026-11-25 11:17)`.
- Fall back to `(dev, <sha>)` when run from source.

**Done when:** *About* shows the commit SHA. **Test required:** `version_label()` contains the SHA when
`_buildinfo` exists and does not crash when it doesn't.

### QA-H2 · Recon → "robots / sitemap / security.txt" ignores the target's scheme and port
**Repro:** open `http://127.0.0.1:8765/`, go to Recon, click **Use current**, then **robots / sitemap / security.txt**.
The result is `robots.txt: not found (HTTP None)`. Site map → **Discover current site** on the same page *does* find
`robots.txt` (`/admin/`, `/backup.zip`).

**Cause:**
- `wyrm/panels/recon.py:108-115` `use_current()` keeps only `QUrl.host()`, which drops the port.
- `wyrm/panels/recon.py:181` hard-codes `intel.well_known(f"https://{d}")`, which forces https and drops the
  port. Any `http://` site, and any site on a non-default port, is wrong.
- `wyrm/security/intel.py:153` records the connection error in `out[name]["error"]`, but
  `recon.py:173` never shows it, so a refused connection reads as "not found (HTTP None)".

**Fix:**
- Keep the *origin* (`scheme://host[:port]`) for the well-known lookup.
  - Store it separately when **Use current** is clicked.
  - When the user types `host:port` or a URL into the Domain box, derive it from that.
  - Default to `https://` only for bare hostnames.
  - Keep `_host_from_text()` for crt.sh / Wayback / Chaos, which really are host-only.
- In `render`, when `x["status"] is None`, show
  `── robots.txt: request failed (<error>)` instead of `not found (HTTP None)`.

**Done when:** the repro lists `/admin/` and `/backup.zip`, and an unreachable host shows "request failed".
**Test required:** unit test that the origin derived from `http://127.0.0.1:8765/x` is `http://127.0.0.1:8765`.

### QA-H3 · Scanner → JS recon ignores the Target field and skips the engagement scope check
**Repro:** in Scanner, set Target to `http://127.0.0.1:8765/api/data` while the active tab is the New-tab page,
then click **JS recon**. Nothing visible happens. The status label that says "Open the page… first" is below
the fold. Every other Scanner button uses the Target field.

**Cause:**
- `wyrm/panels/scanner.py:474` `js_recon()` reads only `self.win.current_view().url()`.
- It never calls `self._authorized(...)`, unlike `port_scan` and `cors`. But it actively downloads every
  same-host external script with `requests.get`.
- The New-engagement dialog promises users that "Active features (JS fetching, …) only run against in-scope hosts".

**Fix:**
1. Resolve the target the same way the other buttons do, via `self._url()`.
   - If the active tab's URL is on the same origin as the target, keep today's behaviour (read scripts from the live DOM).
   - Otherwise, fetch the target page with `requests` and extract `<script src>` and inline scripts with
     `html.parser`.
2. Call `self._authorized(host, "JS recon")` before any network fetch. Keep the read-only DOM path for in-tab
   inline scripts allowed even out of scope, but skip fetching external scripts.
3. When it can't run, show a modal or toast instead of only the status label (same pattern as the CORS-test refusal).

**Done when:** JS recon on the target above lists `/api/v1/internal`, `/api/v1/internal/users/export` and
`/api/data`, and an out-of-scope target is refused before any request is sent.
**Test required:** mock `requests.get` and assert no call is made for an out-of-scope host.

### QA-H4 · Hard-coded secrets go undetected; three secret detectors disagree
**Evidence** (current source, each line tested alone):

| Snippet | Overview (`analyzer.SECRET_PATTERNS`) | Scanner/JS recon (`jsrecon.SECRETS`) | Audit (`audit/passive._SECRETS`) |
|---|---|---|---|
| `var SECRET_TOKEN = "sk_test_51Hxxxx…";` | missed | missed | found |
| `var DB_PASSWORD = "hunter2hunter2hunter2";` | missed | missed | found |
| `const API_SECRET_KEY = "abcdef0123456789abcd";` | missed | missed | missed |

**Cause:** the "generic secret" regexes require the keyword to be directly followed by `=`/`:`
(`analyzer.py:318` also wraps it in `\b…\b`, which fails before `_`). So any `PREFIX_SECRET_SUFFIX`
style name fails. The three lists also drift apart in other ways:
- Stripe `sk_live_` is `{20,}` in one list and `{24,}` in another.
- Its severity is "critical" in one and "high" in another.
- `GOCSPX-`, Twilio, SendGrid and others exist in only some of the lists.

**Fix:**
- Create a single module, `wyrm/security/secrets.py`, with one `PATTERNS` list and one
  `find_secrets(text) -> [(name, matched, severity, start, end)]`. Make `analyzer.py`, `jsrecon.py` and
  `audit/passive.py` all use it (keep their own output shapes and redaction).
- Generic rule: an identifier that *contains* one of `secret|token|passw(or)?d|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret`
  (case-insensitive, may have prefix and suffix word chars), then optional quote, `\s*[:=]\s*`, then a quoted value of 8+ non-space chars.
  Skip obvious placeholders: `xxx`, `changeme`, `your_…_here`, `<…>`, `${…}`, `process.env…`.

**Done when:** all three snippets are detected by all three tools, with the same name and severity.
**Test required:** a parametrized test over the table above that runs through all three call sites.

### QA-H5 · Overview: credentials inside HTML comments are reported only as "Interesting HTML comment" (info)
**Repro:** the fixture's home page contains `<!-- TODO remove: api_key=AKIAIOSFODNN7EXAMPLE password=hunter2 -->`.
Overview lists it as **info**. Audit (current source) reports the same page as **high · AWS access key id**.

**Cause:** `wyrm/security/analyzer.py:256-258` `check_page()` only regex-matches comments against
`INTERESTING_COMMENT`. Comments are never passed through the secret patterns.

**Fix:** in `check_page`, run each comment through the shared `find_secrets` from QA-H4.
- Emit a `"Information disclosure"` issue per secret, using that pattern's severity and masked evidence.
- Keep the info-level "Interesting HTML comment" only when no secret matched.

**Done when:** the repro shows a **high** "AWS access key id in HTML comment".
**Test required:** yes, in `tests/test_audit_checks.py` or a new `tests/test_analyzer.py`.

---

## MEDIUM

### QA-M1 · Same weakness, different severity depending on which tool reports it
| Issue | Overview (`analyzer.py`) | Scanner (`webchecks`) | Audit (`audit/passive.py`) |
|---|---|---|---|
| No Content-Security-Policy | medium (`:97`) | — | low (`:86`) |
| No clickjacking protection | medium (`:166`) | MEDIUM | low (`:88`) |

Severity labels also differ in format:
- Overview shows lowercase (`medium`).
- Scanner and Audit show uppercase (`MEDIUM`).
- JS recon uses `WARNING` (`scanner.py`, `_js_render`), which isn't a severity level at all.

**Fix:**
- Add `wyrm/security/severity.py` with the canonical levels (`critical, high, medium, low, info`) and
  one table of default severities for the shared header and cookie checks. Use it in all three tools.
- Render severities with one helper that uses Title case: `Medium`.
- Replace JS recon's `"warning"` for interesting endpoints with `"info"`, plus the ★ marker that's already there.

**Test required:** assert the CSP and clickjacking severities are equal across `analyzer`, `webchecks` and `passive`.

### QA-M2 · Audit: the live "N issue(s) so far" counter stays at 0 while findings stream in
**Repro:** Audit → **Crawl + scan**. While it runs, 7+ rows are visible but the footer reads
`Auditing 0/11 · crawled 11 request(s) — auditing… · 0 issue(s) so far`.

**Cause:** `wyrm/panels/audit.py:324-328` rebuilds the text only on `_progress`, which fires once per
*completed request*. `_on_finding` (`:340`) increments `_count` but never refreshes the label.
The first progress call also passes the message `"crawled N request(s) — auditing…"` as the `url` argument, which
produces the garbled `Auditing 0/11 · crawled 11 request(s) — auditing…` text.

**Fix:**
- Keep the last `(done, total, url)` on `self`.
- In `_on_finding`, re-render the label with the new count.
- Emit the post-crawl message through a separate path (e.g. `total == 0` or a dedicated signal) so it's not
  formatted as a URL.

### QA-M3 · Scanner panel overflows horizontally at the default dock width
**Repro:** open Security → Scanner at the default width (~970 px panel). A horizontal scrollbar appears.
- The intro text is cut ("…only run on ho").
- The **Clickjacking test** button is cut to "Click…".
- No other panel does this.

**Cause:** the action buttons are added to one fixed `QHBoxLayout` (`wyrm/panels/scanner.py:80-94`), so the
row's minimum width is wider than the panel.

**Fix:** lay the 6 buttons out in a `QGridLayout` of 3 columns, or a flow layout, so they wrap. Make sure the panel
has no horizontal scrollbar at 900 px.

### QA-M4 · `&` in Qt widget labels is rendered as a mnemonic underscore (third time this class has shipped)
Seen in the running app:

| Where | Source | Renders as |
|---|---|---|
| Security sidebar | `wyrm/panels/panel.py:70` `"API & WebSocket"` | `API _WebSocket` |
| API & WebSocket tab checkbox | `wyrm/panels/capture.py:36` `"Capture API & WebSocket traffic"` | `Capture API_WebSocket traffic` |
| Session / auth group box | `wyrm/panels/sessionauth.py:71` `"When to re-login & where to apply"` | `When to re-login _where to apply` |

Also check `dialogs.py:136` `"Privacy & Security"` and `tools.py:42` `"Match & Replace"`. These are safe only
if they're used in widgets that don't parse mnemonics, such as `QComboBox` items or `QLabel` without a buddy.
`FIX_REPORT.md` L-1 fixed one instance of this by hand.

**Fix:**
- Escape each one as `&&`.
- Add `tests/test_ui_labels.py`: AST-scan `wyrm/**/*.py` for string literals passed to `QPushButton`,
  `QCheckBox`, `QRadioButton`, `QGroupBox`, `QToolButton`, `QAction`, `QMenu.addAction`, and the `groups` list
  in `panel.py`. Fail on any single `&` not followed by another `&` or used as an intended mnemonic (allowlist).

---

## LOW

### QA-L1 · Result panes keep the previous page's results after navigation, with no URL shown
**Repro:** run DOM Analysis on page A, navigate to page B. The counts and tree still show A's results with no
indication of which URL they belong to. (This misled the tester into a false "DOM sink missed" report;
DOM Analysis itself is correct.) The same applies to Overview and Scanner → JS recon.

**Fix:** show the analysed URL in each result header, e.g. `127.0.0.1:8765/dom · 1 sinks · …`.
Either clear the results or mark them "(stale — from <url>)" when the active tab's URL changes.

### QA-L2 · Recon: clicks while a lookup is running are dropped silently, and old results stay under new messages
**Repro:** click **robots / sitemap / security.txt**, then immediately click **Subdomains (crt.sh)**.
- The second click does nothing; the busy overlay swallows it.
- After clicking again on an IP target, the IP-guard message appears but the robots results stay in the list.

**Fix:**
- Disable the four source buttons while `self.busy` is active, and re-enable them in `done`.
- `self.items = []; self._render()` before showing a guard or error message.

### QA-L3 · "Add to findings" / "Add all" are enabled in Audit when there are no results
**Cause:** `wyrm/panels/audit.py:129-132`. **Fix:** enable them only when the tree has rows (and a selection, for
"Add to findings"), with the same tooltip pattern as `overview.py:182-185`.

### QA-L4 · Address bar: the first click doesn't select the existing URL
**Repro:** with `127.0.0.1:8765/` in the address bar, click once in it and type a new URL. The text is
*appended*, e.g. `127.0.0.1:8765/http://…`, and because that has spaces/no scheme it becomes a web search.
Chrome and Firefox select all on the first click.

**Fix:** in `wyrm/mainwindow/chrome.py`, on the URL bar's first mouse-press after focus-in, call `selectAll()`
(standard pattern: an event filter that runs `QTimer.singleShot(0, urlbar.selectAll)` on `FocusIn` caused by a mouse click).

### QA-L5 · Site map doesn't record links seen on a page, only URLs actually requested
**Repro:** on the fixture home page (9 links), Site map lists only `/`, `/api/data`, `/favicon.ico`,
`/static/app.js`, `/static/logo.png`. 404 responses (favicon, logo) are listed like normal paths.
**Fix (enhancement):**
- Add the page's same-origin `<a href>` targets with source `linked`. The page-info hook already
  collects page data.
- Show the HTTP status for browsed entries, so 404s are distinguishable.

---

## Verified working (no action needed)

- Shields, Overview (headers, cookies, info disclosure, tech).
- Site map **Discover** (robots).
- Recon IP guard for crt.sh.
- Traffic filter, including regex-breaking input.
- Scanner **CORS test**, with the scope guard and the dialog when there's no engagement.
- **Technologies**, **Clickjacking test**.
- Engagement dialog validation.
- Audit **Crawl + scan** (XSS ×2, SQLi, open redirect, CRLF in the installed build; full set in current source).
- DOM Analysis (source + sink + flow on the real page).
- Intruder payload menu.
- Decoder, Proxy, WebSocket, Workflows, Session/auth, API & WebSocket, OOB, Findings and Add-ons tabs all render.

## Appendix A · Local test fixture (127.0.0.1 only)

A stdlib `http.server` app with:
- `/search?q=` reflected XSS
- `/user?id=` SQLite SQLi with an error message
- `/redirect?next=` open redirect / CRLF
- `/api/*` CORS reflecting `Origin` with credentials, plus an `alg:none` JWT in the body
- `/login` a POST form without a CSRF token, reflecting `user`
- `/debug` 500 with a "Werkzeug Debugger" title and a traceback
- `/fetch?url=` (SSRF-shaped, does not fetch)
- `/dom` `innerHTML` ← `location.hash`
- `/robots.txt` disallowing `/admin/`, `/backup.zip`
- `/.env`, `/.git/HEAD` exposed

The home page has a secret-bearing HTML comment, and `/static/app.js` has `SECRET_TOKEN = "sk_test_…"` plus
API paths. All responses also send:
- `Server: Apache/2.2.15 (CentOS) PHP/5.3.3`
- `X-Powered-By: PHP/5.3.3`
- `Set-Cookie: session=abc123` without flags

It is checked in as `tests/fixtures/vulnlab.py`. Run it with `python tests/fixtures/vulnlab.py`; it binds
`127.0.0.1:8765` only. Its request log is written to `tests/fixtures/vulnlab.py.log`, so add that to `.gitignore`.
