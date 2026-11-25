# Changelog

What's new in each version of Wyrm Browser. The release workflow publishes the section for the current
version (from `wyrm/__init__.py`) as the release description and the in-app **Update** tooltip, so keep the
most important points first. Each build of a version adds an "Also in this build" list automatically.

## v0.5.0

- This build: smoother browsing — the start page now updates in place instead of reloading every time news,
  weather or the vulnerability feed arrives, and Wyrm's own pages no longer flash white when they open.
- The start-page weather reads "4°C Clear" again (the temperature and condition no longer run together).
- No more crash when quitting, including private windows.
- A web page can no longer forge rows in the API & WebSocket capture view; those rows are now labelled
  "page-reported", and capture also records URL/Request bodies, request headers and failed requests.
- Anti-fingerprinting no longer makes you stand out: the WebGL graphics card now matches your real operating
  system, repeated canvas reads give the same result, every frame of a page sees the same values, and your own
  drawings on a page are never altered.
- Your AI Triage API key now lives in the system keychain (macOS Keychain, Windows Credential Manager, Linux
  Secret Service) and is removed from the settings file; Settings → AI has a Test connection button and errors
  show the HTTP status and reason.
- Your browsing history, engagements and findings are now private to your user account on this computer, and
  history is kept in a single place.
- The Proxy panel shows when upstream TLS isn't being verified, and that choice is now per engagement.
- Active scans (nuclei, katana, naabu…) are checked against the engagement scope at the moment they start —
  IP ranges included — and automatic page analysis stays passive.
- Page info now finds postMessage handlers added with addEventListener.
- Faster scans: katana crawls small sites about a third faster and also parses JavaScript for endpoints;
  nuclei's default scan focuses on exposures, misconfigurations, headers and technologies — the same findings
  as the full template set in about half the time — with a fastest "automatic" mode and the full set one click
  away.
- New "Freeze updates" setting (or WYRM_NO_UPDATE=1) for demos and engagements: no automatic app installs and
  no daily tool/template refresh.
- macOS builds are ready for Developer ID signing and notarization (enabled once the signing certificate is
  added to the release workflow).

- Security hardening: anti-fingerprinting no longer reveals that you're using Wyrm and now uses realistic,
  per-session values, so the feature protects your privacy instead of making you easier to single out.
- Web pages can no longer open restricted addresses (internal pages, local files, or in-page scripts), and a
  website can no longer read your browsing history.
- The Security panels now show everything captured from a target site as plain, inert text, and a page can no
  longer forge or inject rows into the Traffic/API view.
- Your AI Triage API key is now encrypted on your device (Windows DPAPI) instead of being kept in plain text.
- The intercepting proxy now protects its certificate-authority key and automatically removes its trusted
  certificate after a crash, so it never lingers.
- Updates now require a verified checksum and reject a damaged or tampered installer; the installer also locks
  down its program folder so other users on the PC can't modify it.
- AI Triage ships with a working default model, the About box shows the Chromium engine version, and Recon now
  reads IP and host:port targets correctly (e.g. 127.0.0.1:8777).
- The Security panel closes with one clear control, and a detached panel closes with Ctrl+W.
- Vertical tabs redesigned as a clean left-hand list (readable titles + favicons), replacing the old rotated
  tab bar that showed an empty panel; the top tab strip hides while it's on.
- Open a local file by typing its plain path (e.g. C:\folder\image.png), not just file://.
- Fixed the Update button: it now shows download progress and responds to the first click (no more clicking
  several times) — clicking while an update is downloading restarts to finish as soon as it's ready.
- Customize backgrounds: a new Gradients set (vibrant multi-colour and a mesh gradient), and the live-wallpaper
  cards now preview each scene (weather, aurora, matrix, particle network, starfield) instead of one gradient.
- Most visited: the start page now shows tiles for the sites you visit most (from your local history), like
  other browsers — remove one with ×, or turn the whole row off in Customize → Start page.
- Deleting a shortcut or bookmark no longer reloads the start page — it updates in place.
- Bookmark the current page with Ctrl+D; mute a noisy tab from its right-click menu.
- Right-click any page for quick security actions: Scan this page, Send to Repeater, and Copy as cURL.
- More tools in the menu: New window (Ctrl+N), Downloads, and a More tools submenu (find, zoom, full screen,
  print, save page, view source, developer tools).
- Separate Weather and Location toggles for the start page, and setting your city now shows matching places to
  pick from (accurate, no more IP guessing).
- Bookmarks bar at the top, like other browsers: your shortcuts and folders (folders open a drop-down menu),
  each showing the site's own logo. Right-click it to add a bookmark or folder; toggle it from the Layout menu
  or with Ctrl+Shift+B. Right-click a folder for Open all / Rename / Delete.
- Redesigned Customize: a centered panel with a left sidebar (Background, Start page) and a card grid — pick a
  wallpaper, upload your own, choose a live wallpaper, solid colour, or none. Hover a card to delete an upload.
- Tidier toolbar: removed the duplicate shield icon. The Shields button opens the security panel, and
  Ctrl+Shift+S still toggles it.
- HTTPS certificate viewer: click the lock in the address bar to see the site's certificate — issuer, validity,
  alternative names, key, signature, the negotiated TLS version and cipher, and the SHA-256 fingerprint, with a
  one-click Copy PEM. It shows expired and self-signed certificates too (handy for testing).
- Cleaner address bar: the https:// scheme is hidden (the lock icon shows security), and right-click adds
  "Paste and go" plus a choice of searching your selection on the web or for vulnerabilities.
- Start-page shortcuts (speed dial): add and remove your own sites, each showing the site's own logo.
- Show or hide the start-page weather and location from Customize → Start page.
- Settings redesigned: a left sidebar with a search box, so you can find any setting fast.
- History: a "Recently closed" section to restore tabs you closed, like other browsers.
- A cleaner update notification with the app logo and tidier "What's new".
- Faster Traffic panel when there are thousands of requests.

## v0.4.0

- Realistic live weather wallpaper (Customize → Live weather): the start-page background is now drawn to look
  real, not abstract — volumetric sunlit clouds, a sky that shifts from dawn to day to dusk to night with sun
  glow and god-rays, parallax rain with ground ripples, depth-layered snow, drifting fog, and storms with
  branching lightning. Runs offline, no video files.
- Accurate weather location: Wyrm now uses your device's location service (Wi-Fi/GPS, like a phone's weather app)
  for a precise city, falling back to IP if that's unavailable. Wrong place? Click the location on the start page
  to set your city by name — your choice always wins.
- Start-page shortcuts (speed dial): a grid of your own sites and tools you can add and remove, like other browsers.
- Vertical tabs (Layout menu → Vertical tabs): move the tab bar to a left panel, like Edge/Arc — handy with many
  tabs. Off by default.
- Clock format: click the start-page clock to switch between 24-hour and AM/PM.

## v0.3.0

- WebSocket frame editing (Security panel → WebSocket): with the intercepting proxy on, every WebSocket frame
  — even over wss:// (TLS) — is decoded and shown live. Turn on "Intercept frames" to pause a text frame, edit
  its payload and forward it, forward it unchanged, or drop it. Developers: Kwan, Oda.
- Workflows (Security panel → Workflows): Caido-style automation pipelines that rewrite live traffic through the
  proxy — set/remove request or response headers, regex find/replace in bodies, force a response status — scoped
  to URLs you choose, applied to HTTPS too. Build, enable and reorder steps; each workflow shows how often it fired.
- Session / auth macros (Security panel → Session / auth): define a login macro (one request). When a response
  looks logged-out (a 401/403, or text you specify), Wyrm re-runs the macro, grabs the fresh session cookies and
  injects them into later in-scope requests — so long Scanner/Intruder runs don't die when the session expires.
  Right-click a proxy flow → Send to Session macro to fill it in.
- Technology logos: Scanner → Technologies now shows each detected technology's logo (the open Wappalyzer icon
  set, fetched on demand and cached locally).

## v0.2.0

- Animated live wallpapers (Customize → Background): Aurora, Matrix rain, Particle network, Starfield — drawn
  by Wyrm itself, no video files, run offline. (Replaces the bundled sample videos; keeps your own image/video upload.)
- Everything's bundled now: Tor and the nuclei templates ship inside the installer, so Tor windows and nuclei
  scans work right after install with no extra download
- The security tools auto-update: when you're online, Wyrm quietly fetches newer ProjectDiscovery releases
  (and nuclei templates) in the background, once a day
- Smarter updates: routine updates (same version line) now install automatically when you restart Wyrm — no
  more clicking "Update" on every build. Only feature/major releases (or unusually large ones) ask you to update
- Intercepting HTTPS proxy (Burp/Caido-style) — Security panel → Proxy. Turn it on (installs a local CA and
  restarts) and every request/response flows through Wyrm: the full messages, with bodies, are captured and
  searchable. Turn on "Intercept responses" to pause a response, edit its body, and forward it to the page.
  Right-click a flow → Send to Repeater / Intruder. Developers: Kwan, Oda.

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
