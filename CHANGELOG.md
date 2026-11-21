# Changelog

What's new in each version of Wyrm Browser. The release workflow publishes the section for the current
version (from `wyrm/__init__.py`) as the release description and the in-app **Update** tooltip, so keep the
most important points first. Each build of a version adds an "Also in this build" list automatically.

## v0.0.3

- Scanner now runs the ProjectDiscovery tools you have installed — subfinder, dnsx, naabu, httpx, katana,
  nuclei, tlsx, asnmap, cdncheck, uncover, mapcidr, alterx — with live results; developer: @kwan
- Only tools actually installed are shown; tools that contact the target run on in-scope hosts only
- Update button now asks "Restart now" or "Later"; choosing Later installs quietly when you close the browser
- Port scanner: nmap options appear only when nmap is installed (built-in TCP scan otherwise)
- Pointing-hand cursor on every clickable control (buttons, checkboxes, tabs, dropdowns)

## v0.0.2

- History: every page you visit, by day, with search and remove (⌘Y / Ctrl+H) — developer: @kwan
- Clear browsing data: history, address-bar history, cookies and cached files in one place — developer: @kwan
- Scanner: port scan of the top 100 TCP ports (uses nmap if installed) for in-scope targets — developer: @kwan
- Scanner: CORS misconfiguration test, after Chen et al., USENIX Security 2018 — developer: @kwan
- Scanner: clickjacking test and framing proof-of-concept, after Huang et al., USENIX Security 2012 — developer: @kwan
- Start-page wallpaper is cached: going back Home or restarting shows it instantly, no re-download
- Recon: ProjectDiscovery Chaos search (~800 public bug-bounty programs) and private windows (from v0.0.1)

## v0.0.1

- Recon: ProjectDiscovery Chaos — search ~800 public bug-bounty programs and load their subdomains
- Recon: subdomains from certificate logs (crt.sh), Wayback Machine URLs, robots.txt / sitemap / security.txt
- Private windows (Ctrl+Shift+N / ⇧⌘N): history, cookies and site data are deleted when you close them
- Tor windows: browse through the Tor network, nothing saved to disk
- Security panel: page security grade, traffic, site map, Intruder, DOM analysis, findings and reports
- Tools: Repeater, Decoder, JWT, Hash, Match & Replace, Comparer, Sequencer and AI Triage
- Shields: blocks ads, trackers, malware and phishing; anti-fingerprinting, HTTPS-Only, encrypted DNS
- Start page: latest cybersecurity news, CISA exploited-vulnerability feed, customizable background
- Search: Security Search for CVEs, IPs and domains, plus logos for every search engine
- One-click updates, reopens your tabs, asks before closing, Red/Blue team modes and a built-in guide (F1)
