"""HTML for internal wyrm:// pages (start page, paper search, error pages), Carbon-style."""
from __future__ import annotations

from html import escape
from urllib.parse import urlparse

from . import engines

THEME = "dark"  # set by the window; internal pages follow the browser theme
MODE = "blue"   # "blue" (defensive) keeps the blue accent; "red" (offensive) swaps it to red

# per-mode accent override, injected after the base CSS so it recolors the internal pages
MODE_CSS = {
    "blue": "",
    "red": (":root{--btn:#da1e28;--btn-hover:#ba1b23;--link:#da1e28;--focus:#da1e28}"
            ":root[data-theme=dark]{--link:#ff8389;--focus:#fa4d56;--btn:#da1e28;--btn-hover:#ba1b23}"),
}

FONTS = "".join(
    f"@font-face{{font-family:'{fam}';src:url('wyrm://assets/fonts/{file}') format('truetype');font-weight:{w}}}"
    for fam, file, w in (("IBM Plex Sans", "IBMPlexSans-Light.ttf", 300), ("IBM Plex Sans", "IBMPlexSans-Regular.ttf", 400),
                         ("IBM Plex Sans", "IBMPlexSans-SemiBold.ttf", 600), ("IBM Plex Mono", "IBMPlexMono-Regular.ttf", 400)))

CSS = FONTS + """
:root{--bg:#ffffff;--layer:#f4f4f4;--layer2:#e0e0e0;--hover:#e8e8e8;--field:#f4f4f4;--fg:#161616;--muted:#525252;
      --helper:#6f6f6f;--line:#e0e0e0;--strong:#8d8d8d;--btn:#0f62fe;--btn-hover:#0353e9;--link:#0f62fe;--focus:#0f62fe;
      --error:#da1e28;--ok-bg:#a7f0ba;--ok-fg:#0e6027}
:root[data-theme=dark]{--bg:#161616;--layer:#262626;--layer2:#393939;--hover:#333333;--field:#262626;--fg:#f4f4f4;
      --muted:#c6c6c6;--helper:#a8a8a8;--line:#393939;--strong:#6f6f6f;--link:#78a9ff;--focus:#ffffff;--error:#fa4d56;
      --ok-bg:#044317;--ok-fg:#6fdc8c}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:400 14px/1.43 'IBM Plex Sans','Helvetica Neue',Arial,sans-serif;
     letter-spacing:.16px;-webkit-font-smoothing:antialiased}
@keyframes wyrmIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
main{max-width:1056px;margin:0 auto;padding:48px 32px 80px;animation:wyrmIn .2s cubic-bezier(.2,.7,.2,1) both}
a{color:var(--link);text-decoration:none} a:hover{text-decoration:underline}
a:focus-visible,button:focus-visible,input:focus-visible{outline:2px solid var(--focus);outline-offset:-2px}
code,kbd,.mono{font-family:'IBM Plex Mono',Menlo,Consolas,monospace;font-size:12px;letter-spacing:.32px}
form{display:flex;gap:0}
input[type=text]{flex:1;font:inherit;height:48px;padding:0 16px;border:0;border-bottom:1px solid var(--strong);border-radius:0;
                 background:var(--field);color:var(--fg);outline:none}
input[type=text]:focus{outline:2px solid var(--focus);outline-offset:-2px}
input::placeholder{color:var(--helper)}
button{font:inherit;height:48px;padding:0 64px 0 16px;border:0;border-radius:0;background:var(--btn);color:#fff;cursor:pointer;text-align:left}
button:hover{background:var(--btn-hover)}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0 0;align-items:center}
.chip{font-size:12px;padding:2px 10px;border-radius:12px;background:var(--layer2);color:var(--fg)}
.chip:hover{background:var(--hover);text-decoration:none}
.card{background:var(--layer);padding:16px;margin:0 0 1px}
.card:hover{background:var(--hover)}
.card h3{margin:0 0 4px;font-size:16px;font-weight:400;line-height:1.5}
.meta{color:var(--muted);font-size:12px;letter-spacing:.32px}
.tldr{margin:8px 0 0;font-size:14px} .tldr b{font-size:12px;font-weight:600;color:var(--muted)}
.abs{margin:6px 0 0;font-size:13px;color:var(--muted);display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden}
.tag{font-size:12px;padding:1px 8px;border-radius:12px;margin-left:8px;vertical-align:2px;background:var(--ok-bg);color:var(--ok-fg)}
.src{font-size:12px;color:var(--muted);background:var(--layer2);border-radius:12px;padding:0 8px;margin-left:4px}
.links{margin-top:8px;font-size:14px;display:flex;gap:24px}
.err{color:var(--error);font-size:12px}
section h2{font-size:14px;font-weight:600;color:var(--fg);margin:48px 0 16px}
h1{font-weight:300}
"""


def _open(title: str, extra_css: str = "") -> str:
    return (f"<!doctype html><html data-theme='{THEME}'><head><meta charset='utf-8'><title>{escape(title)}</title>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<style>{CSS}{MODE_CSS.get(MODE, '')}{extra_css}</style></head>")


def _page(title: str, body: str, extra_css: str = "", main_class: str = "") -> str:
    return _open(title, extra_css) + f"<body><main class='{main_class}'>{body}</main></body></html>"


# ====================================================================== start page
HOME_CSS = """
main.home{max-width:760px;padding-top:7vh;text-align:center}
.logo{width:72px;height:72px;margin:0 auto 18px;display:block}
.wordmark{font-size:26px;font-weight:300;letter-spacing:.3px;margin:0}
.wordmark b{font-weight:600}
.tagline{font-size:14px;color:var(--muted);margin:6px 0 30px}
.modeline{font-size:13px;color:var(--muted);margin:6px 0 28px}
.modeline b{color:var(--btn);font-weight:600;letter-spacing:.3px}
.modeline.red b{color:#da1e28}
form.big{max-width:620px;margin:0 auto;position:relative;display:block}
.big input{width:100%;height:54px;font-size:16px;padding:0 112px 0 48px;text-align:left;
  border:1px solid var(--border);border-radius:0;background:var(--field);color:var(--fg);transition:border-color .15s}
.big input:focus{outline:none;border:2px solid var(--focus)}
.big input::placeholder{color:var(--helper)}
.big .mag{position:absolute;left:18px;top:0;height:54px;display:flex;align-items:center;color:var(--muted)}
.big button{position:absolute;right:0;top:0;height:54px;width:100px;padding:0;text-align:center;border-radius:0}
.ex{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin:16px 0 0}
.ex a{font-family:'IBM Plex Mono',monospace;font-size:12px;padding:5px 12px;border-radius:16px;background:var(--layer);color:var(--fg)}
.ex a:hover{background:var(--hover);text-decoration:none}
.ex .lbl{color:var(--helper);align-self:center;font-size:12px}
.status{display:flex;flex-wrap:wrap;gap:8px;justify-content:center;margin:26px 0 0}
.pill{font-size:12px;padding:4px 12px;border-radius:16px;background:var(--layer);color:var(--muted);display:inline-flex;gap:6px;align-items:center}
.pill b{color:var(--fg);font-weight:600}
.pill .dot{width:7px;height:7px;border-radius:50%;background:#42be65}
.pill.eng{background:transparent;border:1px solid var(--btn);color:var(--fg)}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin:40px 0 0;text-align:left}
.tile{display:block;padding:20px 18px;background:var(--layer);color:var(--fg);border:1px solid var(--line);
  border-radius:0;border-top:2px solid transparent;transition:border-color .14s,background .14s}
.tile:hover{text-decoration:none;background:var(--hover);border-top-color:var(--btn)}
.tile .ico{color:var(--link);height:28px}
.tile .ico svg{width:28px;height:28px}
.tile .t{font-size:15px;font-weight:600;margin:10px 0 2px}
.tile .d{font-size:12px;color:var(--muted);line-height:1.5}
.feed{margin:44px 0 0;text-align:left}
.feed h2{font-size:13px;font-weight:600;color:var(--muted);letter-spacing:.3px;margin:0 0 12px;display:flex;align-items:center;gap:8px}
.feed h2 .live{width:7px;height:7px;border-radius:50%;background:#da1e28;box-shadow:0 0 0 0 rgba(218,30,40,.5);animation:pulse 2s infinite}
@keyframes pulse{0%{box-shadow:0 0 0 0 rgba(218,30,40,.5)}70%{box-shadow:0 0 0 6px rgba(218,30,40,0)}100%{box-shadow:0 0 0 0 rgba(218,30,40,0)}}
.feed a.cve{display:flex;align-items:center;gap:12px;padding:12px 16px;background:var(--layer);border:1px solid var(--line);
  border-radius:0;margin-bottom:8px;color:var(--fg)}
.feed a.cve:hover{text-decoration:none;border-color:var(--btn);background:var(--hover)}
.feed .id{font-family:'IBM Plex Mono',monospace;font-size:13px;font-weight:600;color:var(--link);white-space:nowrap}
.feed .nm{flex:1;font-size:13px;color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.feed .dt{font-size:12px;color:var(--muted);white-space:nowrap}
.feed .rw{font-size:11px;font-weight:600;color:#fff;background:#da1e28;border-radius:10px;padding:1px 8px;white-space:nowrap}
.foot{color:var(--helper);font-size:12px;margin:40px 0 0}
.credit{color:var(--muted);font-size:12px;margin:10px 0 0;letter-spacing:.3px}
.credit b{color:var(--fg);font-weight:600}
@media (max-width:620px){.grid{grid-template-columns:1fr 1fr}}
"""

def _ico(paths: str) -> str:
    return ("<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.7' "
            f"stroke-linecap='round' stroke-linejoin='round'>{paths}</svg>")

TILE_ICONS = {
    "scan": "<path d='M12 3l8 3v5c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6z'/><path d='M9 12l2 2 4-4'/>",
    "cve": "<circle cx='11' cy='11' r='7'/><path d='M21 21l-4.3-4.3'/>",
    "recon": "<circle cx='12' cy='12' r='9'/><path d='M3 12h18'/><path d='M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z'/>",
    "tor": "<path d='M12 2C9 6 7 9 7 13a5 5 0 0 0 10 0c0-4-2-7-5-11z'/><path d='M12 13v5'/>",
    "learn": "<path d='M3 6l9-3 9 3-9 3z'/><path d='M7 9v5c0 1.5 2.5 3 5 3s5-1.5 5-3V9'/><path d='M21 6v6'/>",
    "bounty": "<circle cx='12' cy='12' r='9'/><circle cx='12' cy='12' r='5'/><circle cx='12' cy='12' r='1.4' fill='currentColor'/>",
}

TILES = [  # curated and compact: works for pros and newcomers alike
    ("scan", "Scan this page", "Grade the current page's security in the panel", "wyrm://do?a=scan"),
    ("cve", "Look up a CVE", "Risk-ranked by real-world exploitation (KEV + EPSS)", "wyrm://sec?q=CVE-2021-44228"),
    ("recon", "Recon a domain", "Subdomains, archived URLs and exposed files", "wyrm://do?a=recon"),
    ("tor", "Tor window", "Private browsing through the Tor network", "wyrm://do?a=tor"),
    ("learn", "Learn cybersecurity", "Courses and labs from ByKh", "https://learn.bykh.org/cybersecurity"),
    ("bounty", "Find bug bounties", "Programs you're authorized to test", "https://hackerone.com/directory/programs"),
]
SEV_COLORS = {"critical": "#da1e28", "high": "#ff832b", "medium": "#b28600", "low": "#4589ff", "info": "#6f6f6f"}
SEARCH_ICON = ("<svg width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' "
               "stroke-linecap='round'><circle cx='11' cy='11' r='7'/><path d='M21 21l-4.3-4.3'/></svg>")


def render_home(ctx: dict) -> str:
    from pathlib import Path
    try:
        logo = (Path(__file__).parent / "assets" / "icon.svg").read_text(encoding="utf-8")
        logo = logo[logo.index("<svg"):].replace("<svg", "<svg class='logo'", 1)
    except (OSError, ValueError):
        logo = ""
    eng = ctx.get("engagement")
    if eng:
        total = sum((ctx.get("counts") or {}).values())
        eng_pill = (f"<span class='pill eng'><b>{escape(eng['name'])}</b> · {len(eng['scope'])} in scope"
                    + (f" · {total} findings" if total else "") + "</span>")
    else:
        eng_pill = "<span class='pill'>Personal browsing</span>"
    status = ("<div class='status'>"
              "<span class='pill'><span class='dot'></span>Shields on</span>"
              "<span class='pill'><span class='dot'></span>HTTPS-Only</span>"
              f"<span class='pill'>Search: <b>{escape(ctx.get('engine_name', ''))}</b></span>"
              f"{eng_pill}</div>")
    examples = ("<div class='ex'><span class='lbl'>Try:</span>"
                "<a href='wyrm://sec?q=CVE-2021-44228'>CVE-2021-44228</a>"
                "<a href='wyrm://sec?q=log4j'>log4j</a>"
                "<a href='wyrm://sec?q=1.1.1.1'>1.1.1.1</a>"
                "<a href='wyrm://sec?q=CWE-79'>CWE-79</a></div>")
    tiles = "".join(f"<a class='tile' href='{escape(u, quote=True)}'><div class='ico'>{_ico(TILE_ICONS[key])}</div>"
                    f"<div class='t'>{escape(t)}</div><div class='d'>{escape(d)}</div></a>" for key, t, d, u in TILES)
    feed = ""
    kev = ctx.get("kev") or []
    if kev:
        rows = "".join(
            f"<a class='cve' href='wyrm://sec?q={escape(k['id'])}'><span class='id'>{escape(k['id'])}</span>"
            f"<span class='nm'>{escape(k['vendor'])} {escape(k['product'])} — {escape(k['name'])}</span>"
            + ("<span class='rw'>ransomware</span>" if k.get("ransomware") else "")
            + f"<span class='dt'>{escape(k['added'])}</span></a>" for k in kev)
        feed = ("<section class='feed'><h2><span class='live'></span>LATEST EXPLOITED-IN-THE-WILD VULNERABILITIES "
                "· CISA KEV</h2>" + rows + "</section>")
    mode = ctx.get("mode", "blue")
    mode_line = (f"<p class='modeline {mode}'>"
                 + ("<b>Red team</b> · offensive — recon, test and report. Authorized targets only."
                    if mode == "red" else
                    "<b>Blue team</b> · defensive — protect, analyze and harden.")
                 + "</p>")
    body = (
        f"{logo}"
        "<p class='wordmark'><b>Wyrm</b> Browser</p>"
        + mode_line
        + "<form class='big' action='wyrm://go' method='get'>"
        f"<span class='mag'>{SEARCH_ICON}</span>"
        "<input type='text' name='q' autofocus autocomplete='off' "
        "placeholder='Search the web, or a CVE, IP, domain or URL'>"
        "<button type='submit'>Search</button></form>"
        + examples + status
        + f"<div class='grid'>{tiles}</div>"
        + feed
        + "<p class='foot'>Only test systems you own or are explicitly authorized to test.</p>"
        + "<p class='credit'>Built by <b>ByKh R&amp;D Group</b> · <b>HackPi</b> — Ethical Hackers Group</p>"
    )
    return _page("New tab", body, HOME_CSS, "home")


# ====================================================================== paper search results
def _search_form(q: str = "") -> str:
    return ("<form action='wyrm://search' method='get'>"
            f"<input type='text' name='q' value='{escape(q, quote=True)}' placeholder='Search papers (arXiv + Semantic Scholar)'>"
            "<button>Search</button></form>")


def _engine_chips(q: str) -> str:
    chips = "".join(f"<a class='chip' href='{escape(e.url(q) if q else e.home, quote=True)}'>{escape(e.name)}</a>"
                    for k, e in engines.ENGINES.items() if k != "r")
    return f"<div class='chips'><span class='meta'>Also search on</span>{chips}</div>"


def _status_tag(status):
    return {"saved": "<span class='tag'>Saved</span>", "read": "<span class='tag'>Read</span>"}.get(status, "")


def _paper_card(p: dict, status: str | None) -> str:
    authors = p.get("authors") or []
    a = ", ".join(authors[:4]) + (" et al." if len(authors) > 4 else "")
    bits = [escape(a)] if a else []
    if p.get("year"):
        bits.append(str(p["year"]))
    if p.get("venue"):
        bits.append(escape(p["venue"]))
    if p.get("citations") is not None:
        bits.append(f"{p['citations']:,} citations")
    srcs = "".join(f"<span class='src'>{escape(s)}</span>" for s in p.get("sources", []))
    tldr = f"<p class='tldr'><b>TL;DR</b> {escape(p['tldr'])}</p>" if p.get("tldr") else ""
    abstract = f"<p class='abs'>{escape(p['abstract'])}</p>" if p.get("abstract") and not p.get("tldr") else ""
    links = []
    if p.get("url"):
        links.append(f"<a href='{escape(p['url'], quote=True)}'>Open</a>")
    if p.get("pdf"):
        links.append(f"<a href='{escape(p['pdf'], quote=True)}'>PDF</a>")
    return (f"<div class='card'><h3><a href='{escape(p.get('url') or '#', quote=True)}'>{escape(p.get('title', ''))}</a>"
            f"{_status_tag(status)}</h3><div class='meta'>{' · '.join(bits)} {srcs}</div>{tldr}{abstract}"
            f"<div class='links'>{''.join(links)}</div></div>")


def render_results(query: str, data: dict, status_map: dict[str, str]) -> str:
    results = data.get("results") or []
    errors = "".join(f"<p class='err'>{escape(e)}</p>" for e in data.get("errors") or [])
    known = sum(1 for p in results if p["key"] in status_map)
    summary = (f"<p class='meta' style='margin:24px 0 16px'>{len(results)} results · {known} already in your reading "
               "history · results found by both sources are ranked first</p>")
    cards = "".join(_paper_card(p, status_map.get(p["key"])) for p in results) or "<p class='meta'>No results.</p>"
    return _page(f"{query} - Papers", _search_form(query) + _engine_chips(query) + errors + summary + cards)


def render_message(title: str, msg: str) -> str:
    return _page(title, f"{_search_form()}<p class='err'>{escape(msg)}</p>")


# ====================================================================== HackPi Security Search
SEC_CSS = """
.kind{display:inline-block;font-size:12px;padding:2px 10px;border-radius:12px;background:var(--layer2);margin:24px 0 8px}
h1.q{font-size:32px;font-weight:300;margin:0 0 4px;word-break:break-all}
.lede{color:var(--muted);margin:0 0 24px;font-size:14px}
.pivots{display:flex;flex-wrap:wrap;gap:1px;background:var(--line);border:1px solid var(--line);margin:0 0 8px}
.pivots a{flex:1 1 170px;background:var(--bg);color:var(--fg);padding:12px 16px;font-size:14px;display:flex;
          justify-content:space-between;gap:8px}
.pivots a:hover{background:var(--hover);text-decoration:none}
.pivots a span{color:var(--link)}
table{width:100%;border-collapse:collapse;margin:8px 0 0;font-size:14px}
th{background:var(--layer2);text-align:left;font-weight:600;padding:12px 16px;font-size:14px}
td{background:var(--layer);border-bottom:1px solid var(--line);padding:12px 16px;vertical-align:top}
tr:hover td{background:var(--hover)}
td.id{white-space:nowrap;font-family:'IBM Plex Mono',monospace;font-size:13px}
td .sum{color:var(--muted);font-size:13px;margin-top:4px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.kev{display:inline-block;font-size:12px;padding:1px 8px;border-radius:12px;background:#da1e28;color:#fff;margin-top:4px;white-space:nowrap}
.sev{display:inline-block;font-size:12px;padding:1px 8px;border-radius:12px;color:#fff;white-space:nowrap}
.bar{height:8px;background:var(--layer2);width:96px;margin-top:6px}.bar i{display:block;height:8px;background:#ff832b}
.num{font-family:'IBM Plex Mono',monospace;font-size:13px;white-space:nowrap}
.card2{background:var(--layer);padding:16px;margin:0 0 1px;display:grid;grid-template-columns:160px 1fr;gap:8px 24px}
.card2 dt{color:var(--muted);font-size:12px;letter-spacing:.32px} .card2 dd{margin:0;font-family:'IBM Plex Mono',monospace;font-size:13px}
.note{font-size:12px;color:var(--helper);margin:8px 0 0;letter-spacing:.32px}
.loading{color:var(--muted)}
"""
SEV_BG = {"critical": "#da1e28", "high": "#ff832b", "medium": "#b28600", "low": "#4589ff"}
KIND_LABEL = {"cve": "CVE", "cwe": "Weakness (CWE)", "attack": "ATT&CK technique", "ip": "IP address",
              "domain": "Domain", "hash": "File hash", "keyword": "Keyword"}


def _sec_form(q: str = "") -> str:
    return ("<form action='wyrm://sec' method='get'>"
            f"<input type='text' name='q' value='{escape(q, quote=True)}' placeholder='CVE, product, IP, domain, hash, CWE, ATT&amp;CK ID…'>"
            "<button>Search</button></form>")


def _cve_table(cves: list[dict]) -> str:
    rows = []
    for c in cves[:40]:
        sev = c.get("severity") or ""
        score = f"<span class='sev' style='background:{SEV_BG.get(sev, '#6f6f6f')}'>{c['score']} {sev.title()}</span>" \
            if c.get("score") is not None else "<span class='meta'>n/a</span>"
        ep = c.get("epss")
        epss = (f"<span class='num'>{ep * 100:.1f}%</span><div class='bar'><i style='width:{max(2, ep * 100):.0f}%'></i></div>"
                f"<div class='meta'>top {100 - (c.get('percentile') or 0) * 100:.1f}%</div>") if ep is not None else "<span class='meta'>n/a</span>"
        kev = ""
        if c.get("kev"):
            k = c["kev"]
            ransom = " · ransomware" if (k.get("knownRansomwareCampaignUse") or "").lower() == "known" else ""
            kev = f"<div><span class='kev'>Exploited in the wild{ransom}</span></div><div class='meta'>KEV since {escape(k.get('dateAdded', ''))}</div>"
        ex = "".join(f" <a href='{escape(u, quote=True)}'>exploit ref</a>" for u in c.get("exploit_refs", [])[:2])
        summary = escape(c.get("summary") or (c["kev"] or {}).get("vulnerabilityName", "") if c.get("kev") else c.get("summary") or "")
        rows.append(
            f"<tr><td class='id'><a href='https://nvd.nist.gov/vuln/detail/{c['id']}'>{c['id']}</a>"
            f"<div class='meta'>{escape(c.get('published', ''))}</div></td>"
            f"<td>{kev}<div class='sum'>{summary}</div><div class='meta'>{escape(' '.join(c.get('cwes', [])))}{ex}"
            f" · <a href='https://github.com/search?q={c['id']}&type=repositories&s=updated'>PoC search</a></div></td>"
            f"<td>{epss}</td><td>{score}</td></tr>")
    return ("<table><tr><th>CVE</th><th>Summary</th><th>Exploit likelihood (EPSS)</th><th>CVSS</th></tr>"
            + "".join(rows) + "</table>"
            "<p class='note'>Ranked by: known exploited (CISA KEV) → EPSS 30-day exploit probability → CVSS. "
            "EPSS: Jacobs et al., Digital Threats 2021.</p>")


def render_sec(data: dict) -> str:
    q, kind = data["query"], data["kind"]
    errors = "".join(f"<p class='err'>{escape(e)}</p>" for e in data.get("errors") or [])
    piv = "".join(f"<a href='{escape(u, quote=True)}'>{escape(n)}<span>→</span></a>" for n, u in data["pivots"])
    parts = [_sec_form(q), f"<span class='kind'>{KIND_LABEL.get(kind, kind)}</span>", f"<h1 class='q'>{escape(q)}</h1>"]
    cves = data.get("cves") or []
    if kind == "cve" and cves:
        c = cves[0]
        state = "is <b>known to be exploited in the wild</b> (CISA KEV)" if c.get("kev") else "is not in the CISA KEV catalog"
        ep = f"{c['epss'] * 100:.1f}% probability of exploitation in the next 30 days" if c.get("epss") is not None else "no EPSS score"
        parts.append(f"<p class='lede'>{escape(c['id'])} {state}; {ep}.</p>")
        if c.get("kev"):
            k = c["kev"]
            parts.append("<dl class='card2'>"
                         f"<dt>Vendor / product</dt><dd>{escape(k.get('vendorProject', ''))} {escape(k.get('product', ''))}</dd>"
                         f"<dt>Required action</dt><dd>{escape(k.get('requiredAction', ''))}</dd>"
                         f"<dt>Due date (US federal)</dt><dd>{escape(k.get('dueDate', ''))}</dd></dl>")
        if c.get("vector"):
            parts.append(f"<p class='meta mono'>{escape(c['vector'])}</p>")
    elif kind == "ip":
        card = data.get("card") or {}
        if card.get("not_found"):
            parts.append("<p class='lede'>Shodan InternetDB has no data for this IP (no open ports seen recently).</p>")
        else:
            dl = "".join(f"<dt>{label}</dt><dd>{escape(', '.join(map(str, card.get(key) or [])) or '-')}</dd>"
                         for label, key in (("Open ports", "ports"), ("Hostnames", "hostnames"), ("Tags", "tags"),
                                            ("CPEs", "cpes")))
            parts.append(f"<p class='lede'>Passive data from Shodan InternetDB (no packets sent to the host).</p><dl class='card2'>{dl}</dl>")
    elif kind == "keyword":
        known = sum(1 for c in cves if c.get("kev"))
        parts.append(f"<p class='lede'>{len(cves)} vulnerabilities from NVD, {known} known exploited. "
                     f"{len(data.get('kev') or [])} matching entries in CISA KEV.</p>")
    elif kind in ("domain", "hash", "attack", "cwe"):
        lede = {"domain": "Recon pivots for this domain. Only test it if it's in an authorized scope.",
                "hash": "Look the sample up in malware intelligence sources.",
                "attack": "MITRE ATT&CK technique: detection and emulation resources.",
                "cwe": "Weakness class: definitions, guidance, and the most critical recent CVEs in this class."}[kind]
        parts.append(f"<p class='lede'>{lede}</p>")
    parts.append(errors)
    parts.append(f"<section><h2>Go deeper</h2><div class='pivots'>{piv}</div></section>")
    kev_rows = data.get("kev") or []
    if kev_rows:
        rows = "".join(
            f"<tr><td class='id'><a href='wyrm://sec?q={k['cveID']}'>{k['cveID']}</a><div class='meta'>{escape(k.get('dateAdded', ''))}</div></td>"
            f"<td>{escape(k.get('vendorProject', ''))} {escape(k.get('product', ''))}<div class='sum'>{escape(k.get('vulnerabilityName', ''))}</div></td>"
            f"<td>{'<span class=kev>ransomware</span>' if (k.get('knownRansomwareCampaignUse') or '').lower() == 'known' else ''}</td></tr>"
            for k in kev_rows)
        parts.append("<section><h2>Known exploited in the wild (CISA KEV)</h2><table><tr><th>CVE</th><th>Product</th>"
                     f"<th></th></tr>{rows}</table></section>")
    if cves and not (kind == "cve" and len(cves) == 1):
        title = {"ip": "Vulnerabilities reported for this host", "cwe": "Critical CVEs in this weakness class"}.get(kind, "Vulnerabilities")
        parts.append(f"<section><h2>{title}</h2>{_cve_table(cves)}</section>")
    elif kind == "cve" and cves:
        parts.append(f"<section><h2>Details</h2>{_cve_table(cves)}</section>")
    return _page(f"{q} - Security Search", "".join(parts), SEC_CSS)


# ====================================================================== error pages
ERROR_CSS = """
main.errp{max-width:720px;padding-top:12vh}
.ico{width:64px;height:64px;margin:0 0 32px;color:var(--muted)}
.ico .w1,.ico .w2,.ico .w3{animation:pulse 1.8s ease-in-out infinite}
.ico .w2{animation-delay:.2s}.ico .w3{animation-delay:.4s}
@keyframes pulse{0%,100%{opacity:.15}50%{opacity:1}}
.ico.float{animation:float 3s ease-in-out infinite}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
h1.e{font-size:42px;font-weight:300;line-height:1.19;margin:0 0 16px}
.lead{font-size:16px;line-height:1.5;color:var(--fg);margin:0 0 16px}
ul{color:var(--muted);padding-left:20px;margin:0 0 32px;line-height:1.7}
.code{font-family:'IBM Plex Mono',monospace;font-size:12px;color:var(--helper);background:var(--layer);padding:12px 16px;
      margin:0 0 32px;word-break:break-all}
.actions{display:flex;gap:1px}
.btn{display:inline-flex;align-items:center;height:48px;padding:0 64px 0 16px;background:var(--btn);color:#fff}
.btn:hover{background:var(--btn-hover);text-decoration:none}
.btn.ghost{background:transparent;color:var(--link);padding:0 16px}
.btn.ghost:hover{background:var(--hover)}
.fade{animation:in .24s cubic-bezier(0,0,.38,.9) both}@keyframes in{from{opacity:0;transform:translateY(8px)}}
"""
STROKE = "fill='none' stroke='currentColor' stroke-width='1.2' stroke-linecap='square'"
WIFI_SVG = (f"<svg class='ico' viewBox='0 0 24 24' {STROKE}><path class='w3' d='M2 8.5a15 15 0 0 1 20 0'/>"
            "<path class='w2' d='M5 12a10 10 0 0 1 14 0'/><path class='w1' d='M8.5 15.5a5 5 0 0 1 7 0'/>"
            "<circle cx='12' cy='19' r='1' fill='currentColor'/><path d='M3 3l18 18' stroke='var(--error)'/></svg>")
SITE_SVG = (f"<svg class='ico float' viewBox='0 0 24 24' {STROKE}><rect x='3' y='4' width='18' height='14'/><path d='M3 8h18'/>"
            "<path d='M9.5 11.5l5 4M14.5 11.5l-5 4' stroke='var(--error)'/></svg>")
SHIELD_SVG = (f"<svg class='ico float' viewBox='0 0 24 24' {STROKE}><path d='M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z'/>"
              "<path d='M9 9l6 6M15 9l-6 6' stroke='#ff832b'/></svg>")


THREAT_CSS = ERROR_CSS + """
main.errp.danger h1.e{color:var(--error)}
.reasons{list-style:none;padding:0;margin:0 0 32px;color:var(--fg)}
.reasons li{background:var(--layer);border-left:3px solid var(--error);padding:12px 16px;margin-bottom:1px}
.btn.danger{background:transparent;color:var(--error);padding:0 16px}
.btn.danger:hover{background:var(--hover)}
"""
BIOHAZARD_SVG = (f"<svg class='ico float' viewBox='0 0 24 24' {STROKE} style='color:var(--error)'>"
                 "<path d='M12 3l9.5 17h-19z'/><path d='M12 10v4'/><circle cx='12' cy='17' r='.6' fill='currentColor'/></svg>")


def render_threat(url: str, category: str, verdict: dict) -> str:
    """Interstitial for navigations blocked by threat lists or the smart link check."""
    from urllib.parse import quote
    host = urlparse(url).hostname or url
    title, lead = {
        "malware": ("Dangerous site blocked", f"<b>{escape(host)}</b> is known to distribute malware. Visiting it could "
                    "infect your computer or steal your data."),
        "phishing": ("Phishing site blocked", f"<b>{escape(host)}</b> is a reported phishing site built to steal "
                     "passwords, payment details or crypto wallets."),
        "suspicious": (("This link looks dangerous" if (verdict or {}).get("score", 0) >= 70
                        else "Check this link before continuing"),
                       f"<b>{escape(host)}</b> has warning signs of a fake or phishing site. "
                       "Smart Link Check paused it so you can decide."),
        "ads": ("Ad / malvertising link blocked", f"<b>{escape(host)}</b> is an ad server, a common source of malvertising."),
        "trackers": ("Tracker blocked", f"<b>{escape(host)}</b> is a tracking domain."),
    }.get(category, ("Blocked", escape(host)))
    reasons = "".join(f"<li>{escape(r)}</li>" for r in (verdict or {}).get("reasons", [])) or "<li>Listed by a threat feed</li>"
    allow = f"wyrm://allow?action=allow-threat&host={quote(host)}&url={quote(url, safe='')}"
    body = (f"<div class='fade'>{BIOHAZARD_SVG}<h1 class='e'>{title}</h1><p class='lead'>{lead}</p>"
            f"<ul class='reasons'>{reasons}</ul><p class='code'>{escape(url)}</p>"
            "<div class='actions'><a class='btn' href='javascript:history.length>1?history.back():location.replace(\"wyrm://home\")'>"
            "Back to safety</a>"
            f"<a class='btn danger' href='{escape(allow, quote=True)}'>I understand the risk, continue</a></div></div>")
    return _page(title, body, THREAT_CSS, "errp danger")


def render_https_unavailable(url: str) -> str:
    from urllib.parse import quote
    host = urlparse(url).hostname or url
    allow = f"wyrm://allow?action=allow-http&host={quote(host)}&url={quote(url, safe='')}"
    body = (f"<div class='fade'>{SHIELD_SVG}<h1 class='e'>Secure connection not available</h1>"
            f"<p class='lead'><b>{escape(host)}</b> doesn't support HTTPS. HTTPS-Only mode keeps every connection "
            "encrypted, so the page wasn't loaded over plain HTTP.</p>"
            "<ul><li>On HTTP, anyone on the network can read and change what you send and receive</li>"
            "<li>Never enter passwords or personal details on this site over HTTP</li></ul>"
            "<div class='actions'><a class='btn' href='javascript:history.back()'>Go back</a>"
            f"<a class='btn ghost' href='{escape(allow, quote=True)}'>Continue to HTTP site (not encrypted)</a></div></div>")
    return _page("Secure connection not available", body, ERROR_CSS, "errp")


def render_error(url: str, error: str, code: int, offline: bool, engagement: str | None = None) -> str:
    host = urlparse(url).hostname or url
    if code == -20:
        icon, title = SHIELD_SVG, "Blocked: out of scope"
        lead = (f"<b>{escape(host)}</b> is not in the scope of engagement <b>{escape(engagement or '')}</b>, "
                "and strict mode is on.")
        tips = ["Add the host to the engagement scope if you're authorized to test it",
                "Or turn strict mode off to only flag out-of-scope requests"]
    elif offline:
        icon, title = WIFI_SVG, "No internet connection"
        lead = "Wyrm can't reach the internet right now."
        tips = ["Check your network cable, modem and router", "Reconnect to Wi-Fi",
                "Check that your proxy (Burp/ZAP) is running, if one is configured",
                "This page reloads automatically when you're back online"]
    elif code in (-105, -137):
        icon, title = SITE_SVG, "This site can't be reached"
        lead = f"The server address for <b>{escape(host)}</b> could not be found."
        tips = ["Check the spelling of the address", "The host may only resolve on an internal network or VPN"]
    elif -299 <= code <= -200:
        icon, title = SITE_SVG, "Certificate problem"
        lead = f"The TLS certificate for <b>{escape(host)}</b> could not be verified."
        tips = ["The site may be misconfigured, or traffic is being intercepted",
                "Using Burp or ZAP? Turn on 'Trust the proxy's CA' in Settings"]
    else:
        icon, title = SITE_SVG, "This site can't be reached"
        lead = f"<b>{escape(host)}</b> took too long to respond or refused the connection."
        tips = ["Check your connection", "Check proxy and firewall settings", "Try again in a moment"]
    items = "".join(f"<li>{t}</li>" for t in tips)
    search = engines.ENGINES[engines.DEFAULT_ENGINE].url(host)
    body = (f"<div class='fade'>{icon}<h1 class='e'>{title}</h1><p class='lead'>{lead}</p><ul>{items}</ul>"
            f"<p class='code'>{escape(error or 'Error')} ({code}) · {escape(url)}</p>"
            f"<div class='actions'><a class='btn' href='{escape(url, quote=True)}'>Try again</a>"
            f"<a class='btn ghost' href='{escape(search, quote=True)}'>Search for {escape(host)}</a></div></div>")
    return _page(title, body, ERROR_CSS, "errp")
