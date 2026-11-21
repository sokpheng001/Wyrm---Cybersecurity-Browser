# Wyrm

A privacy and security browser for cybersecurity professionals — and simple enough for everyone.
Chromium engine, built-in ad/malware/phishing protection, Tor windows, anti-fingerprinting, and a full
panel of tools for **authorized** web security testing.

Built by **ByKh R&D Group** and **HackPi — Ethical Hackers Group**
Copyright © 2021–2026 HackPi · Version 1.0.3

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

**2. Install.** Double-click the `.dmg`, then drag **Wyrm** onto the **Applications** folder in the window
that opens. Eject the "The Hidden Browser" disk afterwards.

**3. Allow it to open (first launch only).** macOS will say *"Wyrm is damaged and can't be opened"* or
*"Apple could not verify Wyrm is free of malware"*. It is **not** damaged — macOS says this about every app
downloaded from the internet that isn't signed with a paid Apple Developer ID. Fix it with **one** of these:

- **Terminal (recommended, works on every macOS version).** Open **Terminal** (Applications → Utilities)
  and run:

  ```bash
  xattr -dr com.apple.quarantine /Applications/Wyrm.app
  ```

  Then open Wyrm normally from Applications or Launchpad.

- **System Settings.** Double-click Wyrm once and close the warning. Go to **System Settings → Privacy &
  Security**, scroll down to *"Wyrm was blocked…"*, click **Open Anyway** and enter your password.
  (On macOS 15 and newer, right-click → **Open** no longer works for this.)

Repeat step 3 after installing each new version.

**If it still won't open:**

```bash
# "You can't open the application because it's not supported on this Mac" → you downloaded
# the wrong chip version; check step 1.

# Still "damaged"? Remove the download flags from the whole app and re-seal it:
sudo xattr -cr /Applications/Wyrm.app
codesign --force --deep --sign - /Applications/Wyrm.app
```

**Uninstall:** drag **Wyrm** from Applications to the Trash. To also remove settings and history:

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
rm -rf ~/.local/opt/hiddenbrowser ~/.local/bin/Wyrm ~/.local/share/applications/hiddenbrowser.desktop \
       ~/.local/share/icons/hicolor/512x512/apps/hiddenbrowser.png
```

## What it does

### Browse
- Chromium engine, tabs in a custom title bar, downloads, DevTools (`F12` / `Ctrl+Shift+I`), view-source (`Ctrl+U`)
- **Address bar** understands URLs, plain searches, bangs (`!g !ddg !cve !edb !shodan !crt !h1 !r`), and
  identifiers — type a `CVE-…`, `CWE-…` or `T####` and it goes straight to the right place
- **History autocomplete** with one-click **Clear history** (⋮ menu)
- **Light / Dark / Follow-system** themes
- **Customize the start page background** (bottom-right **Customize** button): rotating cybersecurity
  wallpapers (a new one every 30 min), color themes, your own image, or none
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
- **Tor windows** (⋮ → New Tor window): routes through the Tor network, nothing saved to disk;
  Tor is downloaded from torproject.org and checksum-verified on first use
- Live **CISA KEV** feed (latest exploited-in-the-wild CVEs) on every new tab

### Test (authorized) — the 🛡 Security panel
- **Engagements**: per-target scope with isolated sessions and an authorization gate; IN/OUT-of-scope badge
- **Shields / Overview / Traffic / Site map / Recon / Tools / Findings** tabs
- **Overview**: passive security grade (headers, CSP, TLS, cookies, tech + CVE lookup, JS secrets/endpoints)
- **Traffic**: every request, filterable, with **per-site focus**; route through **Burp/ZAP** (Settings → Network)
- **Site map**: host/path tree built from observed traffic
- **Recon**: subdomains (crt.sh), Wayback URLs, robots/sitemap/security.txt
- **Tools**: Decoder · JWT · Hash · **Repeater** (colored, scope-aware) · **Match & Replace** · **Comparer** ·
  **Sequencer** (token entropy) · **AI Triage**
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
`bash build_unix.sh` (macOS / Linux). GitHub Actions builds **all three** on every `v*` tag and attaches
them to a Release.

## Developers

- **ByKh R&D Group**
- **HackPi — Ethical Hackers Group**

## Credits

Qt WebEngine (Chromium) · ad/tracker blocking via community filter lists (EasyList, EasyPrivacy, uBlock Origin,
URLhaus, phishing-filter) · Tor Project (Tor, stem) · NVD, CISA KEV, FIRST EPSS, OSV, Shodan InternetDB ·
IBM Plex fonts · Carbon Design System. Research informing the design: PriVaricator (anti-fingerprinting),
CSP Is Dead Long Live CSP (CCS 2016), EPSS (FIRST), CiteSee (CHI 2023).

## License

Wyrm is released under the [MIT License](LICENSE) — Copyright © 2021–2026 **ByKh R&D Group**.
You may use, modify and redistribute it, including commercially, as long as the copyright and license
notice are kept. It comes with no warranty.
