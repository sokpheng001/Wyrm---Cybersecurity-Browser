# Third-party notices

Wyrm Browser is open source under the **MIT License** (see `LICENSE`). It bundles and builds on the components
below. This file lists them and their licenses so Wyrm can be redistributed as open source. The per-tool license
texts for the ProjectDiscovery binaries are shipped alongside them in `wyrm/bin/pdtools/licenses/`.

## Runtime engine & Python libraries

| Component | Role | License |
|-----------|------|---------|
| PySide6 / Qt (incl. Qt WebEngine / Chromium) | GUI + browser engine | **LGPL-3.0** (Qt), BSD (Chromium) |
| requests | HTTP client | Apache-2.0 |
| adblock (adblock-rust binding) | Shields filtering | MPL-2.0 |
| stem | Tor control | LGPL-3.0 |
| PySocks | SOCKS proxying | BSD-3-Clause |
| Pillow | image handling | HPND (MIT-style) |
| cryptography | proxy CA / certificates | Apache-2.0 OR BSD-3-Clause |
| certifi | CA bundle for the proxy's upstream TLS | MPL-2.0 |

**LGPL note (Qt, stem):** these are weak-copyleft, compatible with an MIT application as long as they remain
replaceable (they are dynamically linked / separate files in the build) and their license texts ship with Wyrm.
This does not restrict Wyrm's own MIT code.

## Bundled security tools (all MIT)

ProjectDiscovery suite — subfinder, dnsx, naabu, httpx, katana, nuclei, tlsx, asnmap, cdncheck, uncover,
mapcidr, alterx — and the **nuclei-templates** and the **wappalyzergo** fingerprint set: all **MIT**
(© ProjectDiscovery). Downloaded from official releases at build time and SHA-256 verified.

## Tor

The **Tor Expert Bundle** (The Tor Project) — **BSD-3-Clause** — bundled for Tor windows, verified against the
Tor Project's published SHA-256 checksums.

## Fonts

**IBM Plex Sans / Mono** — **SIL Open Font License 1.1**.

## Fingerprints & filter lists

- Shields filter lists (ad/tracker/malware/phishing) — their respective upstream licenses (e.g. EasyList CC-BY-SA).
- Technology fingerprints — via wappalyzergo (MIT).

## Background videos — ACTION NEEDED for a fully-open release

The built-in video wallpapers are currently downloaded at build time from:
- **Big Buck Bunny** (© Blender Foundation) — **CC-BY 3.0** (requires attribution — see below);
- **flower.webm** (MDN) — **CC0 / public domain**;
- a **Jellyfish** sample from test-videos.co.uk — license not clearly stated.

For a fully clean open-source distribution, the recommendation is to ship **CC0 / public-domain only** (keep
flower.webm, drop the Jellyfish clip, and either keep Big Buck Bunny *with the CC-BY attribution below* or drop
it). User-uploaded video backgrounds have no licensing concern.

Attribution if Big Buck Bunny is kept: *"Big Buck Bunny" © 2008 Blender Foundation, licensed CC-BY 3.0
(peach.blender.org).*

---
*If any version's license differs from the above, the upstream project's own LICENSE prevails. Please open an
issue if you spot an inaccuracy.*
