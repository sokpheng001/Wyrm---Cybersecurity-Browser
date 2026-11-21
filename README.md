# Wyrm

A privacy and security browser for cybersecurity professionals — and simple enough for everyone.
Chromium engine, built-in ad/malware/phishing protection, Tor windows, anti-fingerprinting, and a full
panel of tools for **authorized** web security testing.

Built by **ByKh R&D Group** and **HackPi — Ethical Hackers Group**
Copyright © 2021–2026 HackPi · Version 1.0.0

### The name

A **wyrm** (Old English *wyrm*, “serpent/dragon”) is a wingless, coiled dragon — a watchful guardian that
hoards and protects. It fits a browser that stays low, watches every request, and guards the person using it.

## Install

| OS | Download | Install |
|---|---|---|
| Windows 10/11 | `Wyrm-Setup-1.0.0.exe` | Run it and follow the wizard (no admin needed). |
| macOS 12+ | `Wyrm-macos.dmg` | Open it, drag **Wyrm** to Applications. First launch: right-click → **Open**. |
| Linux (x64) | `Wyrm-linux.tar.gz` | `tar xzf Wyrm-linux.tar.gz && ./Wyrm/install.sh` |

Downloads are on the [Releases](../../releases) page. First launch may show a SmartScreen / antivirus
"unknown publisher" notice — see **"Why the warning"** below; it's a false positive from an unsigned build.

## What it does

### Browse
- Chromium engine, tabs in a custom title bar, downloads, DevTools (`F12` / `Ctrl+Shift+I`), view-source (`Ctrl+U`)
- **Address bar** understands URLs, plain searches, bangs (`!g !ddg !cve !edb !shodan !crt !h1 !r`), and
  identifiers — type a `CVE-…`, `CWE-…` or `T####` and it goes straight to the right place
- **History autocomplete** with one-click **Clear history** (⋮ menu)
- **Light / Dark / Follow-system** themes
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
(Windows) or right-click → **Open** (macOS). You can verify any download on [VirusTotal](https://www.virustotal.com).

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
