# Changelog

What's new in each version of Wyrm Browser. The release workflow publishes the section for the current
version (from `wyrm/__init__.py`) as the release description and the in-app **Update** tooltip, so keep the
most important points first. Each build of a version adds an "Also in this build" list automatically.

## v0.2.0

- Everything's bundled now: Tor and the nuclei templates ship inside the installer, so Tor windows and nuclei
  scans work right after install with no extra download
- The security tools auto-update: when you're online, Wyrm quietly fetches newer ProjectDiscovery releases
  (and nuclei templates) in the background, once a day
- Smarter updates: routine updates (same version line) now install automatically when you restart Wyrm — no
  more clicking "Update" on every build. Only feature/major releases (or unusually large ones) ask you to update
- Intercepting HTTPS proxy (Burp/Caido-style) — Security panel → Proxy. Turn it on (installs a local CA and
  restarts) and every request/response flows through Wyrm: the full messages, with bodies, are captured and
  searchable. Turn on "Intercept responses" to pause a response, edit its body, and forward it to the page.
  Right-click a flow → Send to Repeater / Intruder. Developers: @kwan, @oda.

## v0.1.0

- First-run welcome screen introducing Wyrm's main tools
- API & WebSocket capture (Security panel → API & WebSocket): opt-in, shows fetch/XHR calls with request and
  response bodies, and WebSocket frames, from the pages you browse — no proxy needed (read-only; send to Repeater)
- Location control now has three modes (Settings → Privacy): Normal, Hide (deny every request — disappear), or
  Show a chosen location (appear elsewhere, e.g. match your VPN/Tor exit)
- Frosted-glass start page over image/video backgrounds, keeping the IBM Carbon square style
- New OOB Interactions (Security panel → OOB Interactions): a Collaborator-style callback listener to confirm
  blind bugs (blind SSRF, blind XSS, SSTI, XXE, OOB command injection). Start the listener, copy the unique
  payload URL into a target, and watch incoming callbacks (time, source IP, method, path, headers, body).
  It listens on your machine, so it catches callbacks from hosts that can reach you (internal targets, your LAN,
  or any target when Wyrm runs on a public IP / with the port forwarded)
- "Send to" bus: right-click traffic → Send to Repeater / Intruder / Comparer, so the tools work together
- Everything from the 0.0.x line: built-in ProjectDiscovery tools, Intercept, Technologies + JS recon,
  video/image backgrounds, downloads panel, Hacker theme, and many fixes

## v0.0.8

- Downloads button in the toolbar (Ctrl+J) with a downloads panel, like other browsers: see progress, and
  Open or Show-in-folder each finished file (Open now checks the file is there and reports if it can't open it)
- Home page background can now be a video: pick a built-in video wallpaper, or upload your own (Customize →
  Background). Videos are WebM; your uploaded MP4 may not play because Wyrm's engine ships no H.264 codec
- Extensions: clearer note that extensions needing Chrome background APIs (like Wappalyzer) can't fully run in
  Wyrm yet — use Scanner → Technologies for technology detection instead
- New Scanner → JS recon: pulls endpoints, API paths and leaked secrets (AWS, Google, GitHub, Stripe, Slack,
  JWTs, private keys and more) from the open page's scripts — inline and same-scope external (LinkFinder /
  SecretFinder style). Interesting endpoints (admin, token, api, graphql …) are starred
- Home page now shows a live clock, the date, and your location + weather (based on your exit IP, so it follows
  a VPN / Tor; turn it off in Settings)
- Downloads: choose where to save each file (or set a default folder in Settings), and Open / Show-in-folder
  when a download finishes
- Detected technologies now show their category and link straight to CVE searches (Wyrm, NVD, CVE Details),
  with the version included
- Location control (Settings → Privacy): report a chosen position to websites so it matches your VPN/Tor exit,
  not your real GPS ("Use my IP location" fills it in)
- Extensions manager shows each extension's status, and warns when an extension can't fully run in Wyrm
- Fixed: switching tools in the Security panel sometimes needed two clicks
- Fixed: Developer Tools showed two close buttons
- Tor on macOS: load the bundled libraries correctly and clear the download quarantine so it starts

## v0.0.7

- Scanner → Technologies detects far more, with versions and categories: it now inspects the live page like
  Wappalyzer (JavaScript globals, page elements, every script URL, meta tags, cookies, headers) against ~7,700
  open fingerprints. Example: nextjs.org went from 3 to 16 technologies, with Next.js and other versions
- Fixed: response headers (Server, Set-Cookie, ...) of open pages weren't captured

## v0.0.6

- Scanner → Technologies now analyses the page you have open (its HTML and response headers), like Wappalyzer:
  works behind bot checks and logins, and doesn't contact the site again. Leave the target empty to use it
- Intercept button in the toolbar (pause icon, Ctrl+Alt+I); it lights up while requests are being held
- Note: the Wappalyzer extension itself can't run in Wyrm (its background needs Chrome's toolbar API, which
  Qt WebEngine doesn't provide); use Scanner → Technologies instead

## v0.0.5

- Fixed: Wyrm crashed when closing with an extension switched on and an engagement profile open
- Fixed: extension popups closed as soon as you clicked inside them; they now stay open (Esc or click away closes)
- New Extensions button (puzzle piece) in the toolbar: your extensions and their popups in one click
- Intercept (Burp-style), ⋮ → Intercept requests or Ctrl+Alt+I: hold page requests and form submissions, edit the
  method, URL, headers and body, then Forward, Drop, or send to Repeater / Intruder
- Traffic: right-click → Send to Intruder, next to Send to Repeater
- Faster: the window opens about 40% sooner, and ad/tracker checks on every request are 4x faster
- New theme: ⋮ → Theme → Hacker (pro dark), graphite with an orange accent and monospace data views

## v0.0.4

- Fixed: the browser froze or closed after adding an extension, and when it started with one switched on.
  Extensions such as Wappalyzer now install, stay on after a restart and open their popup (⋮ → Extensions)
- Note: Qt WebEngine supports only part of Chrome's extension features, so some extensions may not work
  fully (for example Wappalyzer's toolbar badge); their popups and page features work

## v0.0.3

- Extensions: add Chrome extensions (Manifest V3) from the Chrome Web Store, a .zip / .crx file or a folder
  (⋮ → Extensions); switch them on/off or remove them; never run in private or Tor windows
- Chrome Web Store pages show an “Add to Wyrm Browser” bar: install extensions such as Wappalyzer in one click
- Scanner → Technologies: built-in Wappalyzer-style detection of what a site is built with (CMS,
  frameworks, servers, CDN, analytics)
- Wyrm Shield warnings before adding an extension (what it will be able to do) and before keeping files that
  can run code (programs, scripts, installers, macro documents); the safe choice is always the default
- Security tools: dnsx, tlsx, cdncheck, alterx and katana fixed for the latest tool versions; asnmap
  explains that it needs a free ProjectDiscovery Cloud API key
- Scanner target box takes a domain, URL, host:port, IP, IP range or AS number; each tool gets what it
  needs (https:// or http:// picked automatically, ports kept, ranges for naabu/httpx/tlsx) and
  the status line shows exactly what ran
- Repeater: loading animation while the response Preview renders
- Security tools: fixed "charmap codec can't decode" errors; Stop works instantly; failures say why
- Updates are checked against the release's SHA-256 before installing; Linux now updates in place too
- ProjectDiscovery tools now come built in: subfinder, dnsx, naabu, httpx, katana, nuclei, tlsx, asnmap,
  cdncheck, uncover, mapcidr and alterx are installed with the browser — nothing extra to set up; developer: @kwan
- Windows installer: the security tools are optional ("Browser only"), in case your antivirus objects to them
- Updates install silently: the browser closes and comes back updated, no Setup window
- Each release lists SHA-256 checksums of every download, so you can verify what you installed
- Scanner now runs the ProjectDiscovery tools you have installed — subfinder, dnsx, naabu, httpx, katana,
  nuclei, tlsx, asnmap, cdncheck, uncover, mapcidr, alterx — with live results; developer: @kwan
- Tools that contact the target run on in-scope hosts only
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
