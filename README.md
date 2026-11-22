# Wyrm

A privacy and security browser for cybersecurity professionals — and simple enough for everyone.
Chromium engine, built-in ad/malware/phishing protection, Tor windows, anti-fingerprinting, and a full
panel of tools for **authorized** web security testing.

Built by **[ByKh R&D Group](https://bykh.org)** and **HackPi — Ethical Hackers Group** · Website: [bykh.org](https://bykh.org)
Copyright © 2023–present ByKh R&D Group · Version 0.3.0

### History

Wyrm was developed by **ByKh R&D Group** from **2023 to 2025** and had its **first public release in 2026**
(v0.0.1). Every release since then is published on the [Releases](../../releases) page.

### The name

A **wyrm** (Old English *wyrm*, “serpent/dragon”) is a wingless, coiled dragon — a watchful guardian that
hoards and protects. It fits a browser that stays low, watches every request, and guards the person using it.

## Install

Download the file for your computer from the [Releases](../../releases) page (open the latest release →
**Assets**).

| Your computer | File to download |
|---|---|
| Windows 10/11 (64-bit) | `Wyrm-Setup-<version>.exe` |
| Mac with Apple Silicon (M1, M2, M3, M4…) | `Wyrm-macos-arm64.dmg` |
| Mac with Intel processor | `Wyrm-macos-intel.dmg` |
| Linux (x64) | `Wyrm-linux.tar.gz` |

> Wyrm is free and not yet signed with a paid Apple / Microsoft publisher certificate, so the first launch
> shows a security warning. This is expected — the steps below get past it. See
> [Why the warning](#why-the-warning-smartscreen--antivirus).

### macOS (12 Monterey or newer)

**1. Which Mac do I have?** Apple menu  → **About This Mac**.
"Chip: Apple M…" → download `Wyrm-macos-arm64.dmg`. "Processor: Intel…" → download `Wyrm-macos-intel.dmg`.
Or in Terminal:

```bash
uname -m      # arm64 = Apple Silicon, x86_64 = Intel
```

**2. Install.** Double-click the `.dmg`, then drag **Wyrm Browser** onto the **Applications** folder in the window
that opens. Eject the "Wyrm Browser" disk afterwards.

**3. Allow it to open (first launch only).** macOS will say *"Wyrm is damaged and can't be opened"* or
*"Apple could not verify Wyrm is free of malware"*. It is **not** damaged — macOS says this about every app
downloaded from the internet that isn't signed with a paid Apple Developer ID. Fix it with **one** of these:

- **Terminal (recommended, works on every macOS version).** Open **Terminal** (Applications → Utilities)
  and run:

  ```bash
  xattr -dr com.apple.quarantine "/Applications/Wyrm Browser.app"
  ```

  Then open Wyrm Browser normally from Applications or Launchpad.

- **System Settings.** Double-click Wyrm once and close the warning. Go to **System Settings → Privacy &
  Security**, scroll down to *"Wyrm was blocked…"*, click **Open Anyway** and enter your password.
  (On macOS 15 and newer, right-click → **Open** no longer works for this.)

Repeat step 3 after installing each new version.

**If it still won't open:**

```bash
# "You can't open the application because it's not supported on this Mac" → you downloaded
# the wrong chip version; check step 1.

# Still "damaged"? Remove the download flags from the whole app and re-seal it:
sudo xattr -cr "/Applications/Wyrm Browser.app"
codesign --force --deep --sign - "/Applications/Wyrm Browser.app"
```

**Uninstall:** drag **Wyrm Browser** from Applications to the Trash. To also remove settings and history:

```bash
rm -rf ~/Library/Application\ Support/HackPi/Wyrm ~/Library/Caches/HackPi/Wyrm ~/Library/Preferences/com.hackpi.Wyrm.plist
```

### Windows 10/11

1. Run `Wyrm-Setup-<version>.exe` (no administrator rights needed).
2. If **"Windows protected your PC"** (SmartScreen) appears, click **More info → Run anyway**.
3. Follow the wizard. Wyrm is added to the Start menu.

**Uninstall:** Settings → Apps → Installed apps → **Wyrm** → Uninstall.

### Linux (x64)

```bash
tar xzf Wyrm-linux.tar.gz
./Wyrm/install.sh            # installs for your user only (~/.local), no sudo needed
```

Then start **Wyrm** from your app menu, or run `Wyrm` in a terminal (make sure `~/.local/bin` is on your
`PATH`). If it fails to start with a Qt / `xcb` error, install the usual runtime libraries
(Debian/Ubuntu):

```bash
sudo apt install libegl1 libxkbcommon-x11-0 libxcb-cursor0 libnss3 libxcomposite1 libxdamage1 libxrandr2 libxtst6
```

**Uninstall:**

```bash
rm -rf ~/.local/opt/wyrm ~/.local/bin/Wyrm ~/.local/share/applications/wyrm.desktop \
       ~/.local/share/icons/hicolor/512x512/apps/wyrm.png
```

## What it does

### Browse
- Chromium engine, tabs in a custom title bar, downloads, DevTools (`F12` / `Ctrl+Shift+I`), view-source (`Ctrl+U`)
- **Address bar** understands URLs, plain searches, bangs (`!g !ddg !cve !edb !shodan !crt !h1 !r`), and
  identifiers — type a `CVE-…`, `CWE-…` or `T####` and it goes straight to the right place
- **History** page (⋮ → History, `⌘Y` / `Ctrl+H`): visited pages by day, search, remove; address-bar autocomplete
- **Clear browsing data** (⋮ menu, `Ctrl+Shift+Delete`): history, address-bar history, cookies, cached files
  (history, clearing and the Scanner below: developer Kwan)
- **Light / Dark / Follow-system** themes
- **Customize the start page background** (bottom-right **Customize** button): rotating cybersecurity
  wallpapers (change every 5 min … daily — your choice), color themes, your own image, or none
- **Update button** (top-right, like Brave): appears only when a newer release is published here
- **Built-in guide**: ⋮ → **Help — how to use Wyrm**, `F1`, or the *How to use Wyrm* link on the start page
- **Latest cybersecurity news** on the start page (The Hacker News, BleepingComputer, Krebs, SecurityWeek,
  Dark Reading, The Record) — shown while online, refreshed every 30 minutes
- **Red team / Blue team modes** (⋮ menu or the header chip): swap an offensive (red) vs defensive (blue)
  accent and start-page emphasis — IBM Carbon styling throughout

### Stay private & safe (Shields)
- Block **ads, trackers, malware, phishing, pop-ups**, remove **YouTube ads**, strip tracking parameters —
  all toggleable, per-site or globally (turn Shields off for one site to analyze its ads for malvertising)
- **Anti-fingerprinting** (canvas/WebGL/audio noise + attribute normalization)
- **HTTPS-Only** mode and **encrypted DNS (DNS-over-HTTPS)**
- **Smart Link Check** — dangerous/suspicious links are paused with the reasons shown
- **Private windows** (⋮ → New private window, `Ctrl+Shift+N` / `⇧⌘N`): like incognito — an in-memory
  profile; history, cookies and site data are deleted when the window closes
- **Tor windows** (⋮ → New Tor window): routes through the Tor network, nothing saved to disk;
  Tor is downloaded from torproject.org and checksum-verified on first use
- Live **CISA KEV** feed (latest exploited-in-the-wild CVEs) on every new tab

### Test (authorized) — the 🛡 Security panel
- **Engagements**: per-target scope with isolated sessions and an authorization gate; IN/OUT-of-scope badge
- **Shields / Overview / Traffic / Site map / Recon / Scanner / Intruder / Tools / Proxy / WebSocket / Workflows /
  Session / auth / API & WebSocket / OOB / Findings** tabs
- **Scanner** (developer: Kwan): port scan (top 100 TCP; nmap if installed, otherwise built-in),
  **CORS misconfiguration test** (after Chen et al., USENIX Security 2018) and **clickjacking test** with a
  framing proof-of-concept (after Huang et al., USENIX Security 2012) — active checks only on in-scope hosts
- **ProjectDiscovery tools** in Scanner (developer: Kwan): if you have them installed, run **subfinder, dnsx,
  naabu, httpx, katana, nuclei, tlsx, asnmap, cdncheck, uncover, mapcidr, alterx** with live results; only
  installed tools are shown, and tools that contact the target run on in-scope hosts only
- **Overview**: passive security grade (headers, CSP, TLS, cookies, tech + CVE lookup, JS secrets/endpoints)
- **Traffic**: every request, filterable, with **per-site focus**; route through **Burp/ZAP** (Settings → Network)
- **Site map**: host/path tree built from observed traffic
- **Recon**: subdomains (crt.sh), Wayback URLs, robots/sitemap/security.txt, and **ProjectDiscovery Chaos** —
  search public bug-bounty programs and load their published subdomains (passive, no API key; developer: Oda)
- **Tools**: Decoder · JWT · Hash · **Repeater** (per-tab sessions, raw edit, raw/preview, copy-as-cURL) ·
  **Match & Replace** · **Comparer** · **Sequencer** (token entropy) · **AI Triage**
- **Intercepting proxy** (Proxy tab; developers: Kwan, Oda): routes the browser's own traffic through a local
  Burp/Caido-style proxy that terminates HTTPS with a local CA. Full request/response history **with bodies** and
  full-text search; **Intercept requests** to pause, edit or drop *any* request (XHR and API calls too), and
  **Intercept responses** to edit a response before the page sees it; right-click → Send to Repeater / Intruder /
  Session macro
- **WebSocket** (developers: Kwan, Oda): every WebSocket frame over **wss://** is decoded and shown live; edit a
  text frame's payload and forward it, forward unchanged, or drop it
- **Workflows**: Caido-style automation pipelines on live traffic — set/remove headers, regex find/replace in
  bodies, force a status — scoped to URLs you choose; each workflow shows how often it fired
- **Session / auth**: a login macro that re-runs when a response looks logged-out (401/403 or a body pattern),
  grabs fresh session cookies and injects them into later in-scope requests — so long Scanner/Intruder runs don't die
- **AI Triage**: a scope-gated, human-in-the-loop, non-destructive assistant that analyzes a request/response
  or code and proposes findings, safe verification steps, and remediation (bring your own API key, Settings → AI)
- **Findings → report**: export HTML or Markdown
- **Security Search** (default engine): CVE/CWE/IP/domain/hash intel, ranked by real-world risk
  (CISA KEV → EPSS → CVSS), with recon and bug-bounty pivots

> **Only test systems you own or have explicit written permission to test.**
> Wyrm is built for defensive work and authorized testing. It deliberately has **no** unthrottled
> fuzzing/brute-force, credential stuffing, or automated exploitation.

Shortcuts: `Ctrl+T/W` tabs · `Ctrl+L` address bar · `Ctrl+Shift+S` security panel · `Ctrl+Shift+F` add finding ·
`Ctrl+Alt+N` Tor window · `Ctrl+,` settings · `F12` inspect · `Ctrl+U` view source.

## Use cases

**Bug-bounty hunting (recon → report):**
1. Create an **Engagement** and set the target scope (the IN/OUT-of-scope badge and authorization gate keep you honest).
2. **Recon** — subdomains (crt.sh with a Cert Spotter fallback), Wayback URLs, robots/sitemap/security.txt, Chaos
   bug-bounty data; **Scanner** — subfinder, httpx, katana, nuclei, naabu… (if installed).
3. Browse the app with the **intercepting proxy** on — full request/response history (with bodies) is captured and searchable.
4. **Intercept a request** (XHR/API calls too), tamper a parameter or header, then Forward — or Drop it.
5. Send interesting requests to **Repeater** to iterate, or **Intruder** to fuzz an ID/parameter.
6. Confirm blind bugs (SSRF/XXE) with **OOB Interactions** (Collaborator-style callbacks).
7. Record **Findings** and export an **HTML / Markdown report**.

**API & web-app testing:**
- Inspect/decode **JWTs**, hashes and encoded values in **Tools**.
- **Match & Replace** / **Workflows** to strip CSP, inject headers or rewrite responses live across the whole session.
- **Session / auth** macros re-login automatically so long Scanner / Intruder runs don't die when the session expires.

**Real-time / WebSocket apps:**
- See every **WebSocket** frame over `wss://`, edit a frame's payload before it's sent, or drop it.

**Blue team / internal review:**
- Passive **Overview** security grade (headers, CSP, TLS, cookies, tech + CVE) on any page you open.
- **Security Search** for CVE / CWE / IP / domain / hash intel, ranked by real-world risk (CISA KEV → EPSS → CVSS).

**Everyday private browsing (companies & individuals):**
- Shields block ads / trackers / malware / phishing, anti-fingerprinting, HTTPS-Only + encrypted DNS, and
  private / Tor windows — the security panel stays out of the way until you open it.

> **Only test systems you own or have explicit written permission to test.**

## Why the warning (SmartScreen / antivirus)

New, independently-published apps aren't yet signed with a paid publisher certificate, and PyInstaller's
start-up stub resembles a self-extractor — so Windows SmartScreen or some AV engines may flag the installer
as "unknown publisher" or a false positive. It is **not** infected. To run it: **More info → Run anyway**
(Windows) or follow the macOS step 3 under **Install** above. You can verify any download on [VirusTotal](https://www.virustotal.com).

## Build from source

Requires Python 3.11+.

```bash
pip install -r requirements.txt
python run.py                 # run
python run.py --tor           # run a Tor window
```

Installers: `./build_windows.ps1` (Windows, needs [Inno Setup](https://jrsoftware.org/isinfo.php)) or
`bash build_unix.sh` (macOS / Linux).

### Releases are automatic

Every push to `wyrm-browser` is built on GitHub Actions for Windows, macOS (Apple Silicon + Intel) and
Linux. **Only if all builds succeed** is it released, numbered automatically as the previous release + 1
(0.0.1 → 0.0.2 → …). Installed copies then show the **Update** button and update themselves in place
(Windows: silent installer; macOS: the app is replaced and relaunched). Only the newest release is kept.
Add `[skip release]` to a commit message to push without releasing; bump `__version__` in
`wyrm/__init__.py` yourself only for a bigger jump (e.g. 0.1.0).

## Project structure

```
run.py                 app entry (normal, --private, --tor windows)
wyrm/
  mainwindow/          the main window, one module per area (tabs, search, session, home, privacy,
                       engagement, appearance, docks, chrome, menu, updates, tor, downloads, papers, layout)
  panels/              the Security panel, one module per tab (overview, traffic, recon, scanner, tools, intruder,
                       dom, proxy, wsintercept, workflows, sessionauth, capture, oob, sitemap, shields, findings)
                       + panel.py / common.py
  browser/             web-engine pieces: injected scripts, request interceptor, tab view
  ui/                  shared UI: icons/constants, one-click updater
  security/            recon, analysis & proxy engines (no UI): secsearch, chaos, analyzer, intel, news, mitm,
                       wsframe, workflows, sessionauth, techdetect, pdtools, oob, …
  pages.py · scheme.py internal wyrm:// pages (start page, guide, search results)
  theme.py · widgets.py styling and reusable widgets
installer/ · build_*   installers and build scripts; .github/workflows/build.yml = automatic releases
```

## Developers

Wyrm is built and maintained by **[ByKh R&D Group](https://bykh.org)** and **HackPi — Ethical Hackers Group**:

- **Oda**
- **Kwan**
- **Kim**
- **Lida**
- **Naly**
- **Buri**
- **Vatanny**

## Credits

Qt WebEngine (Chromium) · ad/tracker blocking via community filter lists (EasyList, EasyPrivacy, uBlock Origin,
URLhaus, phishing-filter) · Tor Project (Tor, stem) · NVD, CISA KEV, FIRST EPSS, OSV, Shodan InternetDB ·
IBM Plex fonts · Carbon Design System. Research informing the design: PriVaricator (anti-fingerprinting),
CSP Is Dead Long Live CSP (CCS 2016), EPSS (FIRST), CiteSee (CHI 2023).

## License

Wyrm is released under the [MIT License](LICENSE) — Copyright © 2023–present **ByKh R&D Group**.
You may use, modify and redistribute it, including commercially, as long as the copyright and license
notice are kept. It comes with no warranty.
