# Wyrm

A privacy and security browser for cybersecurity professionals.
Chromium engine, built-in ad/malware/phishing protection, Tor windows, and tools for authorized web security testing.

Built by **ByKh R&D Group** and **HackPi — Ethical Hackers Group**
Copyright © 2021–2026 HackPi · Version 1.0.0

### The name

A **wyrm** (Old English *wyrm*, “serpent/dragon”) is a wingless, coiled dragon from Norse and Germanic myth —
a watchful guardian that hoards and protects. It fits a browser that stays low, watches every request, and guards
the person using it. The coiled-dragon logo comes from the same idea.

## Install

| OS | Download | Install |
|---|---|---|
| Windows 10/11 | `Wyrm-Setup-1.0.0.exe` | Run it and follow the wizard (no admin needed). |
| macOS 12+ | `Wyrm-macos.dmg` | Open it, drag **Wyrm** to Applications. First launch: right-click → **Open**. |
| Linux (x64) | `Wyrm-linux.tar.gz` | `tar xzf Wyrm-linux.tar.gz && ./Wyrm/install.sh` |

Downloads are on the [Releases](../../releases) page.

## Use

- **Search:** type anything in the address bar. The default **Security Search** understands CVEs, products, IPs,
  domains, hashes, CWE and ATT&CK IDs, and ranks vulnerabilities by real-world risk (CISA KEV → EPSS → CVSS).
  Other engines: `!g` Google, `!ddg` DuckDuckGo, `!cve` NVD, `!edb` Exploit-DB, `!shodan`, `!crt`, `!h1`.
- **Shields** (toolbar shield with a number): blocks ads, trackers, malware, phishing, pop-ups and YouTube ads,
  strips tracking parameters, and shows a report of everything blocked. Toggle per site.
- **Smart Link Check:** hover a link to see if it looks like phishing. Dangerous or suspicious links always ask
  before opening, with the reasons shown. Right-click → **Check this link** any time.
- **Inspect:** right-click → **Inspect** (or `F12` / `Ctrl+Shift+I`) opens the developer tools; `Ctrl+U` views source.
- **Encrypted connections:** HTTPS-Only mode and encrypted DNS (DNS-over-HTTPS) are on by default.
- **Tor window:** Menu (⋮) → **New Tor window**. Routes everything through the Tor network, saves nothing to disk.
- **Security testing:** pick or create an **engagement** (dropdown left of the address bar) with your authorized
  scope. The 🛡 panel then gives passive page analysis, traffic log, recon, tools (Decoder, JWT, Hash, Repeater,
  Match & Replace) and a findings report.
- **Theme:** Menu (⋮) → Theme → Follow system / Dark / Light.

Shortcuts: `Ctrl+T` new tab · `Ctrl+W` close · `Ctrl+L` address bar · `Ctrl+Shift+S` security panel ·
`Ctrl+Shift+F` add finding · `Ctrl+Alt+N` Tor window · `F12` / `Ctrl+Shift+I` inspect · `Ctrl+U` view source.

> Only test systems you own or have written permission to test.

## Build from source

Requires Python 3.11+.

```bash
pip install -r requirements.txt
python run.py                 # run
python run.py --tor           # run a Tor window
```

Installers: `.\build_windows.ps1` (Windows, needs [Inno Setup](https://jrsoftware.org/isinfo.php)) or
`bash build_unix.sh` (macOS / Linux). GitHub Actions builds all three on every `v*` tag.

## Developers

- **ByKh R&D Group**
- **HackPi — Ethical Hackers Group**

## Credits

Qt WebEngine (Chromium) · Brave adblock-rust · Tor Project (Tor, stem) · EasyList, EasyPrivacy, uBlock Origin,
URLhaus, phishing-filter lists · NVD, CISA KEV, FIRST EPSS, OSV, Shodan InternetDB · IBM Plex fonts · Carbon Design System.
