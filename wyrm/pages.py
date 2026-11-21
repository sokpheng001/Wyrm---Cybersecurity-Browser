#------------------------------------------------------------------------------
# Wyrm — wyrm/pages.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""HTML for internal wyrm:// pages (start page, paper search, error pages), Carbon-style."""
from __future__ import annotations

import base64
import secrets
from html import escape
from urllib.parse import urlparse

# Random 4K hacker / cybersecurity / technology / quantum wallpaper, fetched live via the wyrm://bg
# handler (same-origin, never blocked/cached). It also auto-rotates every 30 minutes on open start pages.
BG_SOURCES = [
    "https://loremflickr.com/3840/2160/hacker,cybersecurity,technology,quantum,circuit,matrix,code",
    "https://picsum.photos/3840/2160",
]
BG_ROTATE_MS = 30 * 60 * 1000  # how often the wallpaper changes; set by the window from the user's choice
# choices offered in Customize → "Change every" (minutes, label)
BG_INTERVALS = [(5, "5 min"), (15, "15 min"), (30, "30 min"), (60, "1 hour"), (360, "6 hours"), (1440, "Daily")]
BG_INTERVAL_LABEL = dict(BG_INTERVALS)
# start-page background colors the user can pick in "Customize" (key, label, CSS background-image)
BG_COLORS = [
    ("midnight", "Midnight", "linear-gradient(135deg,#0b1020,#1c2541)"),
    ("wyrm", "Wyrm blue", "linear-gradient(135deg,#001141,#0f62fe)"),
    ("teal", "Deep teal", "linear-gradient(135deg,#04211f,#007d79)"),
    ("forest", "Forest", "linear-gradient(135deg,#071908,#198038)"),
    ("purple", "Violet", "linear-gradient(135deg,#1c0f30,#6929c4)"),
    ("crimson", "Crimson", "linear-gradient(135deg,#2d0709,#a2191f)"),
    ("sunset", "Sunset", "linear-gradient(135deg,#3e1a00,#d4500f)"),
    ("graphite", "Graphite", "linear-gradient(135deg,#121212,#3d3d3d)"),
]
BG_COLOR_CSS = {k: css for k, _, css in BG_COLORS}

from . import engines
from . import years as _years

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
/* search boxes on the Papers / Security pages: Search label centered (typed text stays left-aligned) */
.qform button{padding:0 32px;text-align:center}
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
.credit a{color:inherit} .credit a:hover{text-decoration:underline}
body.hasbg .credit a{color:#fff}
.copy{color:var(--helper);font-size:12px;margin:6px 0 24px;letter-spacing:.3px}
body.hasbg .copy{color:#e0e0e0;text-shadow:0 1px 10px rgba(0,0,0,.6)}
body.hasbg .copy a{color:#fff;text-decoration:underline}
/* latest cybersecurity news */
.news a.it{display:flex;align-items:center;gap:12px;padding:12px 16px;background:var(--layer);border:1px solid var(--line);
  border-top:0;color:var(--fg)}
.news a.it:first-of-type{border-top:1px solid var(--line)}
.news a.it:hover{text-decoration:none;border-color:var(--btn);background:var(--hover)}
.news .srcc{flex:none;width:140px;display:flex;justify-content:center}  /* fixed column so titles line up */
.news .src{display:inline-block;font-size:11px;font-weight:600;line-height:20px;color:var(--link);white-space:nowrap;
  text-align:center;padding:0 10px;margin:0;border-radius:10px}  /* pill hugs the source name */
.news .tt{flex:1;font-size:13px;color:var(--fg);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.news .dt{font-size:12px;color:var(--muted);white-space:nowrap}
.feed h2 .live.blue{background:var(--btn);animation:none}
body.hasbg .news a.it{background:rgba(255,255,255,.88);border-color:rgba(0,0,0,.08);color:#161616;backdrop-filter:blur(6px)}
body.hasbg .news .tt{color:#161616}
:root[data-theme=dark] body.hasbg .news a.it{background:rgba(20,20,28,.72);border-color:rgba(255,255,255,.12)}
:root[data-theme=dark] body.hasbg .news .tt{color:#f4f4f4}

/* "Customize": button bottom-right like other browsers; the panel opens centered over a dimmed page */
details.cust{position:fixed;right:20px;bottom:20px;z-index:50;text-align:left}
details.cust summary{list-style:none;cursor:pointer;display:flex;align-items:center;gap:8px;font-size:13px;font-weight:600;
  padding:9px 16px;border-radius:20px;background:var(--layer);color:var(--fg);border:1px solid var(--line);
  box-shadow:0 2px 10px rgba(0,0,0,.18)}
details.cust summary::-webkit-details-marker{display:none}
details.cust summary:hover{background:var(--hover)}
details.cust[open] summary{background:var(--btn);color:#fff;border-color:var(--btn)}
details.cust summary{position:relative;z-index:1}
details.cust[open]::before{content:"";position:fixed;inset:0;background:rgba(0,0,0,.55);backdrop-filter:blur(2px)}
.cpanel{position:fixed;left:50%;top:50%;transform:translate(-50%,-50%);width:min(440px,calc(100vw - 32px));
  max-height:calc(100vh - 48px);overflow:auto;padding:20px 20px 16px;background:var(--layer);color:var(--fg);
  border:1px solid var(--line);box-shadow:0 12px 48px rgba(0,0,0,.45)}
.cpanel .hd{display:flex;align-items:center;justify-content:space-between;margin:0 0 12px}
.cpanel .hd h3{margin:0}
.cpanel .x{display:flex;align-items:center;justify-content:center;width:32px;height:32px;color:var(--fg);cursor:pointer}
.cpanel .x:hover{background:var(--hover)}
.cpanel .ivs{display:flex;flex-wrap:wrap;gap:6px;margin:4px 0 0}
.cpanel .iv{font-size:12px;padding:5px 12px;border-radius:14px;background:var(--layer2);color:var(--fg)}
.cpanel .iv:hover{background:var(--hover);text-decoration:none}
.cpanel .iv.on{background:var(--btn);color:#fff;font-weight:600}
.cpanel .note{font-size:12px;color:var(--muted);margin:6px 0 0}
.cpanel h3{font-size:14px;font-weight:600;margin:0 0 12px}
.cpanel h4{font-size:12px;font-weight:600;color:var(--muted);margin:16px 0 8px;letter-spacing:.3px}
.cpanel .opt{display:flex;align-items:center;gap:12px;padding:8px;color:var(--fg);border:2px solid transparent}
.cpanel .opt:hover{background:var(--hover);text-decoration:none}
.cpanel .opt.on{border-color:var(--btn)}
.cpanel .opt .pv{width:56px;height:36px;flex:none;background-size:cover;background-position:center;border:1px solid var(--line)}
.cpanel .opt .pv.photo{background:linear-gradient(135deg,#0f62fe,#8a3ffc 50%,#da1e28)}
.cpanel .opt .pv.plain{background:var(--bg)}
.cpanel .opt .pv.up{display:flex;align-items:center;justify-content:center;font-size:20px;color:var(--muted)}
.cpanel .opt b{display:block;font-size:13px;font-weight:600}
.cpanel .opt small{display:block;font-size:12px;color:var(--muted)}
.cpanel .sws{display:grid;grid-template-columns:repeat(4,1fr);gap:8px}
.cpanel .sw{height:40px;border:2px solid transparent;outline:1px solid var(--line)}
.cpanel .sw:hover{outline:2px solid var(--fg)}
.cpanel .sw.on{border-color:#fff;outline:2px solid var(--btn)}

/* daily background photo (Brave-style): full-bleed, with a scrim so content stays legible */
body.hasbg{background:#0b0b10}
body.hasbg::before{content:"";position:fixed;inset:0;z-index:-2;background-size:cover;background-position:center;
  background-attachment:fixed;background-image:var(--wyrm-bg);opacity:0;transition:opacity 1.1s ease}
body.hasbg.bg-ready::before{opacity:1}  /* fade in once the image has loaded: no pop / blink */
/* next wallpaper: loaded off-screen, then cross-faded over the current one */
#bgnext{position:fixed;inset:0;z-index:-2;background-size:cover;background-position:center;opacity:0;
  transition:opacity 1.6s ease;pointer-events:none}
#bgnext.on{opacity:1}
body.hasbg::after{content:"";position:fixed;inset:0;z-index:-1;
  background:linear-gradient(180deg,rgba(8,8,14,.55),rgba(8,8,14,.72))}
body.hasbg .wordmark,body.hasbg .tagline,body.hasbg .modeline,body.hasbg .foot,body.hasbg .credit{color:#f4f4f4;text-shadow:0 1px 10px rgba(0,0,0,.6)}
body.hasbg .logo{filter:drop-shadow(0 2px 10px rgba(0,0,0,.5))}
/* cards follow the theme — light & translucent in light mode, dark & translucent in dark mode */
body.hasbg .pill{background:rgba(255,255,255,.80);color:#161616;backdrop-filter:blur(6px)}
body.hasbg .pill b{color:#161616}
body.hasbg .tile,body.hasbg .feed a.cve{background:rgba(255,255,255,.88);border-color:rgba(0,0,0,.08);color:#161616;backdrop-filter:blur(6px)}
body.hasbg .tile .d{color:#525252}
body.hasbg .feed .nm{color:#161616}
body.hasbg .ex a{background:rgba(255,255,255,.82);color:#161616}
:root[data-theme=dark] body.hasbg .pill{background:rgba(255,255,255,.12);color:#f4f4f4}
:root[data-theme=dark] body.hasbg .pill b{color:#fff}
:root[data-theme=dark] body.hasbg .tile,:root[data-theme=dark] body.hasbg .feed a.cve{background:rgba(20,20,28,.72);border-color:rgba(255,255,255,.12);color:#f4f4f4}
:root[data-theme=dark] body.hasbg .tile .d{color:#c6c6c6}
:root[data-theme=dark] body.hasbg .feed .nm{color:#f4f4f4}
:root[data-theme=dark] body.hasbg .ex a{background:rgba(255,255,255,.12);color:#f4f4f4}
body.hasbg .credit b,body.hasbg .modeline b{color:#ffffff}
body.hasbg .foot{color:#e0e0e0}
body.hasbg .feed h2{color:#f4f4f4;text-shadow:0 1px 8px rgba(0,0,0,.6)}
/* ---- responsive start page: medium (side panel open / small window) and narrow widths ---- */
main.home{padding-bottom:96px}  /* room so the floating Customize button never covers the last row */
@media (max-width:820px){
  main.home{padding-left:20px;padding-right:20px}
  .grid{grid-template-columns:1fr 1fr;gap:12px}
  .news .srcc{width:124px;justify-content:flex-start}
  .news .tt,.feed .nm{white-space:normal;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;line-height:1.4}
  .feed a.cve,.news a.it{align-items:flex-start;padding:12px 14px}
  .feed .dt,.news .dt{padding-top:1px}
}
@media (max-width:560px){
  main.home{padding-top:4vh;padding-left:14px;padding-right:14px}
  .logo{width:56px;height:56px;margin-bottom:12px}
  .wordmark{font-size:22px}
  .big input{padding-right:92px}
  .big button{width:84px}
  .grid{grid-template-columns:1fr}
  .tile{padding:14px 16px}
  /* news: source + time on one line, headline underneath */
  .news a.it{flex-wrap:wrap;gap:4px 10px}
  .news .tt{order:3;flex-basis:100%}
  .news .dt{margin-left:auto}
  .feed a.cve{flex-wrap:wrap;gap:4px 10px}
  .feed .nm{order:3;flex-basis:100%}
  .feed .dt{margin-left:auto}
  details.cust{right:12px;bottom:12px}
  details.cust summary{padding:8px 12px}
}
"""

# Tor window start page: purple field + a faint onion watermark, drawn with inline SVG (no network).
_TOR_ONION_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' width='340' height='340' viewBox='0 0 24 24' fill='none' "
    "stroke='#9b5de5' stroke-width='0.6' opacity='0.55'>"
    "<circle cx='12' cy='13' r='8.2'/><circle cx='12' cy='13' r='5.4'/><circle cx='12' cy='13' r='2.6'/>"
    "<path d='M12 4.8V2'/><path d='M9.2 5.4C9.2 3.8 10.3 3 12 3'/><path d='M14.8 5.4C14.8 3.8 13.7 3 12 3'/>"
    "</svg>")
_TOR_ONION = "data:image/svg+xml;base64," + base64.b64encode(_TOR_ONION_SVG.encode()).decode()
TOR_BG_CSS = (
    "body.tor::before{background:radial-gradient(circle at 50% 30%,#3c2252 0%,#20122e 55%,#0e0818 100%)!important;"
    "opacity:1}"
    f"body.tor::after{{background:url('{_TOR_ONION}') center 24%/300px no-repeat,"
    "linear-gradient(180deg,rgba(14,8,24,.25),rgba(14,8,24,.55))!important}"
    "body.tor .wordmark b{color:#c9a6ff}"
)

def _ico(paths: str) -> str:
    return ("<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.7' "
            f"stroke-linecap='round' stroke-linejoin='round'>{paths}</svg>")

TILE_ICONS = {
    "scan": "<path d='M12 3l8 3v5c0 5-3.5 8-8 10-4.5-2-8-5-8-10V6z'/><path d='M9 12l2 2 4-4'/>",
    "cve": "<circle cx='11' cy='11' r='7'/><path d='M21 21l-4.3-4.3'/>",
    "recon": "<circle cx='12' cy='12' r='9'/><path d='M3 12h18'/><path d='M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z'/>",
    "tor": ("<path d='M12 6.5c-1.2 2.4-7 4.6-7 9.2a7 7 0 0 0 14 0c0-4.6-5.8-6.8-7-9.2z'/>"   # onion bulb
            "<path d='M12 10c-.9 1.8-4.3 3.1-4.3 5.9a4.3 4.3 0 0 0 8.6 0c0-2.8-3.4-4.1-4.3-5.9z'/>"      # middle layer
            "<path d='M12 13.4c-.5 1-1.8 1.6-1.8 2.7a1.8 1.8 0 0 0 3.6 0c0-1.1-1.3-1.7-1.8-2.7z'/>"     # core
            "<path d='M12 6.5V4.2'/><path d='M12 4.6c.6-1.6 2-2.3 3.8-2.2'/>"),                        # sprout
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
    news_html = ""
    news = ctx.get("news") or []
    if news:
        from .security.news import ago
        rows = "".join(
            f"<a class='it' href='{escape(n['url'], quote=True)}' title='{escape(n['title'], quote=True)}'>"
            f"<span class='srcc'><span class='src'>{escape(n['source'])}</span></span><span class='tt'>{escape(n['title'])}</span>"
            f"<span class='dt'>{escape(ago(n['date']))}</span></a>" for n in news)
        news_html = ("<section class='feed news'><h2><span class='live blue'></span>LATEST CYBERSECURITY NEWS</h2>"
                     + rows + "</section>")
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
        + news_html + feed
        + "<p class='foot'>Only test systems you own or are explicitly authorized to test.</p>"
        + "<p class='credit'>Built by <a href='https://bykh.org' title='bykh.org'><b>ByKh R&amp;D Group</b></a>"
          " · <b>HackPi</b> — Ethical Hackers Group · <a href='https://bykh.org'>bykh.org</a></p>"
        + f"<p class='copy'><a href='wyrm://help'>How to use Wyrm</a> · © {_years()} ByKh R&amp;D Group · MIT License</p>"
    )
    if ctx.get("tor"):   # Tor window: purple + onion watermark background instead of a web photo
        html = _page("New tab", body, HOME_CSS + TOR_BG_CSS, "home")
        return html.replace("<body>", "<body class='hasbg tor'>", 1)
    bgc = ctx.get("bg") or {"mode": "random" if ctx.get("background") else "none"}
    bmode = bgc.get("mode", "random")
    # Customize lives outside <main>: main's entry animation would otherwise trap position:fixed inside it
    panel = _customize_panel(bgc)

    def page(css: str, cls: str = "") -> str:
        html = _page("New tab", body, css, "home").replace("</main>", "</main>" + panel + BG_FADE_JS, 1)
        return html.replace("<body>", f"<body class='{cls}'>", 1) if cls else html
    if bmode == "random":  # 4K tech/hacker wallpaper via wyrm://bg; same image for the chosen interval
        url = f"wyrm://bg?r={secrets.token_hex(6)}"
        # switch when the current wallpaper expires (time left comes from the handler), then every interval
        left = int(ctx.get("bg_ms_left") or BG_ROTATE_MS) + 1000  # BG_ROTATE_MS = the user's interval
        # soft change: preload the next wallpaper, cross-fade it in, then make it the base layer
        body += ("<script>(function(){function swap(){var u='wyrm://bg?r='+Date.now(),im=new Image();"
                 "im.onload=function(){var n=document.createElement('div');n.id='bgnext';"
                 "n.style.backgroundImage=\"url('\"+u+\"')\";document.body.appendChild(n);"
                 "requestAnimationFrame(function(){requestAnimationFrame(function(){n.classList.add('on');});});"
                 "setTimeout(function(){document.documentElement.style.setProperty('--wyrm-bg',\"url('\"+u+\"')\");"
                 "setTimeout(function(){n.remove();},120);},1700);};im.src=u;}"
                 f"setTimeout(function(){{swap();setInterval(swap,{BG_ROTATE_MS});}},{left});}})();</script>")
        return page(HOME_CSS + f"\n:root{{--wyrm-bg:url('{url}')}}", "hasbg")
    if bmode == "color" and bgc.get("color") in BG_COLOR_CSS:
        return page(HOME_CSS + f"\n:root{{--wyrm-bg:{BG_COLOR_CSS[bgc['color']]}}}"
                    "\nbody.hasbg::after{background:rgba(0,0,0,.12)}", "hasbg")
    if bmode == "image" and bgc.get("image_ver"):  # the user's own picture, served by wyrm://bgimg
        return page(HOME_CSS + f"\n:root{{--wyrm-bg:url('wyrm://bgimg?v={escape(str(bgc['image_ver']))}')}}", "hasbg")
    return page(HOME_CSS)


# fades the start-page background in once its image is ready (colors are ready at once)
BG_FADE_JS = ("<script>(function(){var b=document.body;if(!b.classList.contains('hasbg'))return;"
              "var v=getComputedStyle(document.documentElement).getPropertyValue('--wyrm-bg'),"
              "m=/url\\(['\"]?([^'\")]+)['\"]?\\)/.exec(v);"
              "function ready(){b.classList.add('bg-ready');}"
              "if(!m){requestAnimationFrame(ready);return;}"
              "var im=new Image();im.onload=im.onerror=ready;im.src=m[1];})();</script>")


def _customize_panel(bgc: dict) -> str:
    """Bottom-right "Customize" button: a centered panel to pick the start-page background and how often the
    wallpaper changes (applied instantly, remembered). Stays open after a choice (wyrm://home#customize)."""
    m = bgc.get("mode", "random")
    has_img = bool(bgc.get("image_ver"))
    every = int(bgc.get("interval") or 30)
    every_lbl = BG_INTERVAL_LABEL.get(every, f"{every} min")
    every_txt = "once a day" if every == 1440 else f"every {every_lbl}"

    def opt(href, pv, title, sub, on):
        return (f"<a class='opt{' on' if on else ''}' href='{href}'><span class='pv {pv}'>{'+' if pv == 'up' else ''}</span>"
                f"<span><b>{title}</b><small>{sub}</small></span></a>")
    opts = opt("wyrm://do?a=bg&amp;mode=random", "photo", "Wyrm wallpapers",
               f"Cybersecurity &amp; tech photos, new one {every_txt}", m == "random")
    if has_img:
        opts += (f"<a class='opt{' on' if m == 'image' else ''}' href='wyrm://do?a=bg&amp;mode=image'>"
                 f"<span class='pv' style=\"background-image:url('wyrm://bgimg?v={escape(str(bgc['image_ver']))}')\">"
                 "</span><span><b>Your image</b><small>The picture you uploaded</small></span></a>")
    opts += opt("wyrm://do?a=bg-upload", "up", "Upload from device…" if not has_img else "Upload another image…",
                "JPG, PNG, WebP or GIF, up to 25 MB", False)
    opts += opt("wyrm://do?a=bg&amp;mode=none", "plain", "No background", "Plain light / dark theme", m == "none")
    ivs = "".join(f"<a class='iv{' on' if mins == every else ''}' href='wyrm://do?a=bg-interval&amp;min={mins}'>{lbl}</a>"
                  for mins, lbl in BG_INTERVALS)
    sws = "".join(f"<a class='sw{' on' if m == 'color' and bgc.get('color') == k else ''}' title='{escape(label)}' "
                  f"href='wyrm://do?a=bg&amp;mode=color&amp;color={k}' style='background:{css}'></a>"
                  for k, label, css in BG_COLORS)
    pencil = ("<svg width='16' height='16' viewBox='0 0 16 16' aria-hidden='true'><path fill='currentColor' "
              "d='M11.3 1.3a1 1 0 0 1 1.4 0l2 2a1 1 0 0 1 0 1.4L6 13.4 2 14l.6-4 8.7-8.7zM4.4 10.6l-.3 1.3 1.3-.3 "
              "7.6-7.6-1-1-7.6 7.6z'/></svg>")
    close = ("<a class='x' role='button' aria-label='Close' title='Close'><svg width='16' height='16' viewBox='0 0 16 16' "
             "aria-hidden='true'><path d='M3 3l10 10M13 3L3 13' stroke='currentColor' stroke-width='1.6'/></svg></a>")
    # open after a choice (#customize), close on Esc / outside click / ×
    js = ("<script>(function(){var d=document.querySelector('details.cust');if(!d)return;"
          "if(location.hash==='#customize'){d.open=true;history.replaceState(null,'',location.pathname+location.search);}"
          "d.querySelector('.x').addEventListener('click',function(e){e.preventDefault();d.open=false;});"
          "document.addEventListener('keydown',function(e){if(e.key==='Escape')d.open=false;});"
          "document.addEventListener('click',function(e){if(d.open&&!e.target.closest('.cpanel')"
          "&&!e.target.closest('summary'))d.open=false;});})();</script>")
    return (f"<details class='cust'><summary>{pencil}Customize</summary><div class='cpanel'>"
            f"<div class='hd'><h3>Background</h3>{close}</div>{opts}"
            f"<h4>CHANGE WALLPAPER EVERY</h4><div class='ivs'>{ivs}</div>"
            + ("" if m == "random" else "<p class='note'>Applies when Wyrm wallpapers is selected.</p>")
            + f"<h4>COLORS</h4><div class='sws'>{sws}</div></div></details>{js}")


# ====================================================================== paper search results
def _search_form(q: str = "") -> str:
    return ("<form class='qform' action='wyrm://search' method='get'>"
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
    return ("<form class='qform' action='wyrm://sec' method='get'>"
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


# ====================================================================== built-in user guide (wyrm://help)
HELP_CSS = """
main.help{max-width:1080px;display:grid;grid-template-columns:220px 1fr;gap:40px;align-items:start}
.help nav{position:sticky;top:24px;font-size:13px}
.help nav b{display:block;font-size:12px;color:var(--muted);letter-spacing:.3px;margin:0 0 8px}
.help nav a{display:block;padding:6px 10px;color:var(--fg);border-left:2px solid var(--line)}
.help nav a:hover{text-decoration:none;background:var(--hover);border-left-color:var(--btn)}
.help h1{font-size:30px;font-weight:300;margin:0 0 6px}
.help .lead{color:var(--muted);font-size:15px;margin:0 0 28px;line-height:1.6}
.help section{padding:8px 0 22px;border-top:1px solid var(--line)}
.help section:first-of-type{border-top:0}
.help h2{font-size:20px;font-weight:600;margin:18px 0 10px;scroll-margin-top:16px}
.help h3{font-size:14px;font-weight:600;margin:16px 0 6px}
.help p,.help li{font-size:14px;line-height:1.65}
.help ul,.help ol{padding-left:22px;margin:6px 0}
.help kbd{display:inline-block;font-size:12px;padding:1px 7px;border:1px solid var(--strong);border-bottom-width:2px;
  border-radius:4px;background:var(--layer);color:var(--fg);white-space:nowrap}
.help table{border-collapse:collapse;width:100%;font-size:14px;margin:8px 0}
.help td{padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
.help td:first-child{white-space:nowrap;width:1%}
.help .note{background:var(--layer);border-left:3px solid var(--btn);padding:12px 16px;margin:12px 0;font-size:14px;line-height:1.6}
.help .warn{border-left-color:var(--error)}
.help pre{background:var(--layer);padding:12px 16px;overflow:auto;font-size:13px}
.help .top{font-size:12px}
@media (max-width:820px){
  main.help{grid-template-columns:1fr;gap:8px;padding-left:20px;padding-right:20px}
  .help nav{position:static;display:flex;flex-wrap:wrap;gap:6px;margin-bottom:12px}
  .help nav b{flex-basis:100%}
  .help nav a{border:1px solid var(--line);padding:4px 10px}
  .help td:first-child{white-space:normal}
}
"""


def render_help(mac: bool = False) -> str:
    """Built-in 'How to use Wyrm' guide. Shortcuts are shown the way this OS spells them."""
    mod, alt, sh = ("⌘", "⌥", "⇧") if mac else ("Ctrl", "Alt", "Shift")

    def k(*keys):
        return "+".join(f"<kbd>{escape(x)}</kbd>" for x in keys)
    sections = [
        ("start", "Getting started", f"""
<p>Wyrm is a privacy and security browser. Use it like any browser — and when you need it, the
<b>Security panel</b> gives you professional tools for <b>authorized</b> web security testing.</p>
<ol>
<li>Type a website, a search, or a security identifier in the <b>address bar</b> ({k(mod, "L")}) and press Enter.</li>
<li>Open a new tab with {k(mod, "T")}; close it with {k(mod, "W")}.</li>
<li>Click the <b>shield</b> button in the toolbar ({k(mod, sh, "S")}) to open the Security panel.</li>
<li>Everything else is in the <b>⋮ menu</b> at the right of the toolbar: Settings, themes, Tor window, updates and this guide.</li>
</ol>"""),
        ("search", "Searching", f"""
<p>The address bar understands more than web addresses:</p>
<table>
<tr><td><b>Website</b></td><td><code>example.com</code> — opens it (always over HTTPS when HTTPS-Only is on).</td></tr>
<tr><td><b>Search</b></td><td>Any words — searched with the engine chosen in the dropdown next to the address bar.</td></tr>
<tr><td><b>CVE / CWE / ATT&amp;CK</b></td><td><code>CVE-2021-44228</code>, <code>CWE-79</code>, <code>T1059</code> — go straight to the right intel page.</td></tr>
<tr><td><b>IP, domain, hash</b></td><td>Opens <b>Security Search</b>: reputation, related CVEs and recon pivots.</td></tr>
<tr><td><b>Bangs</b></td><td><code>!g</code> Google · <code>!ddg</code> DuckDuckGo · <code>!cve</code> NVD · <code>!edb</code> Exploit-DB ·
<code>!shodan</code> · <code>!crt</code> certificates · <code>!h1</code> HackerOne · <code>!r</code> Reddit — e.g. <code>!cve log4j</code></td></tr>
</table>
<p>Change the default engine with the dropdown beside the address bar. <b>Security Search</b> ranks vulnerabilities by
real-world risk: exploited in the wild (CISA KEV) first, then exploit probability (EPSS), then CVSS.</p>"""),
        ("home", "The start page", """
<ul>
<li><b>Search box</b> and quick examples to try.</li>
<li><b>Tiles</b>: scan the current page, look up a CVE, recon a domain, open a Tor window, learn, find bug bounties.</li>
<li><b>Latest cybersecurity news</b> from trusted security news sites — shown while you are online, refreshed every 30 minutes.</li>
<li><b>Latest exploited vulnerabilities</b> from the CISA KEV catalog — click one for details.</li>
</ul>
<h3>Change the background</h3>
<p>Click <b>Customize</b> (bottom-right of the start page) and choose:</p>
<ul>
<li><b>Wyrm wallpapers</b> — cybersecurity &amp; technology photos. Under <b>Change wallpaper every</b>, pick 5 min,
15 min, 30 min, 1 hour, 6 hours or Daily. Reloading the page keeps the same photo until that time has passed.</li>
<li><b>Upload from device</b> — your own JPG, PNG, WebP or GIF (up to 25 MB, kept only on this computer).</li>
<li><b>Colors</b> — eight color themes, or <b>No background</b> for the plain light/dark look.</li>
</ul>"""),
        ("shields", "Privacy &amp; Shields", """
<p>Shields are on by default and block <b>ads, trackers, malware, phishing and pop-ups</b>, remove YouTube ads,
strip tracking parameters from links and resist browser fingerprinting.</p>
<ul>
<li>See what was blocked on the current site in <b>Security panel → Shields</b>.</li>
<li>Turn Shields off <b>for one site</b> with <i>Shields up for this site</i> (useful if a site breaks, or to study its ads).</li>
<li><b>HTTPS-Only</b> upgrades every connection to HTTPS; if a site has no HTTPS you are asked before continuing.</li>
<li><b>Encrypted DNS</b> (DNS-over-HTTPS) hides which sites you look up — choose the provider in the Shields page.</li>
<li><b>Smart Link Check</b> pauses suspicious links and shows why. Right-click any link → <i>Check this link</i>.</li>
<li>Right-click a link → <i>Copy clean link</i> copies it without tracking parameters.</li>
</ul>"""),
        ("tor", "Tor windows", f"""
<p>⋮ → <b>New Tor window</b> ({k(mod, alt, "N")}) opens a purple window that routes all traffic through the Tor
network. Nothing from it is saved to disk. The first time, Wyrm downloads Tor from torproject.org and verifies it.</p>
<p>In a Tor window, ⋮ → <b>New Tor identity</b> gets a fresh circuit; <b>Disconnect Tor</b> closes the window.</p>"""),
        ("panel", "The Security panel", """
<p>Open it with the shield button. The sections on the left:</p>
<table>
<tr><td><b>Shields</b></td><td>What was blocked, and all protection settings.</td></tr>
<tr><td><b>Overview</b></td><td>A passive security grade for the open page: headers, CSP, TLS, cookies, technologies with known CVEs, secrets and endpoints in JavaScript.</td></tr>
<tr><td><b>Site map</b></td><td>The hosts and paths seen while you browse.</td></tr>
<tr><td><b>Recon</b></td><td>Subdomains (certificate logs), archived URLs (Wayback Machine), robots.txt, sitemap and security.txt.</td></tr>
<tr><td><b>Traffic</b></td><td>Every request the page makes, filterable. Can route through Burp Suite or ZAP (Settings → Network).</td></tr>
<tr><td><b>Intruder</b></td><td>Mark positions with <code>§…§</code> and try one payload per line — in-scope targets only, with a rate limit and a request budget.</td></tr>
<tr><td><b>DOM Analysis</b></td><td>Passive scan of the page's scripts for DOM-XSS sources and sinks. Read-only — never runs payloads.</td></tr>
<tr><td><b>Tools</b></td><td>Decoder, JWT, Hash, Repeater, Match &amp; Replace, Comparer, Sequencer and AI Triage.</td></tr>
<tr><td><b>Findings</b></td><td>Your notes and issues; export a report as HTML or Markdown.</td></tr>
</table>
<p>Drag the panel's edge to resize it, or drag its title to move it to the other side or float it.</p>"""),
        ("engage", "Engagements &amp; findings", f"""
<p>An <b>engagement</b> is a security test of a target you are authorized to test. Choose <b>New engagement…</b>
from the dropdown left of the address bar and enter the scope (domains). Each engagement has its own isolated
session (cookies, storage) and its own findings. An <b>IN SCOPE / OUT OF SCOPE</b> badge shows where you are.</p>
<p>Add a finding for the current page with the flag button ({k(mod, sh, "F")}). Export all findings from the
<b>Findings</b> section. Switch back to <b>Personal</b> for normal browsing.</p>
<div class='note warn'><b>Only test systems you own or have explicit written permission to test.</b> Wyrm deliberately has
no unthrottled fuzzing, brute-forcing, credential stuffing or automated exploitation.</div>"""),
        ("modes", "Red team / Blue team, themes", """
<p>The chip at the top-left switches between <b>Blue team</b> (defensive) and <b>Red team</b> (offensive)
emphasis and accent color. ⋮ → <b>Theme</b> chooses Light, Dark or Follow system.</p>"""),
        ("keys", "Keyboard shortcuts", f"""
<table>
<tr><td>{k(mod, "T")} / {k(mod, "W")}</td><td>New tab / close tab</td></tr>
<tr><td>{k(mod, sh, "T")}</td><td>Reopen closed tab</td></tr>
<tr><td>{k(mod, "Tab")} · {k(mod, "1")}…{k(mod, "9")}</td><td>Next tab · go to tab</td></tr>
<tr><td>{k(mod, "L")}</td><td>Address bar</td></tr>
<tr><td>{k(mod, "F")} · {k(mod, "G")}</td><td>Find in page · find next</td></tr>
<tr><td>{k("F5")} or {k(mod, "R")}</td><td>Reload</td></tr>
<tr><td>{k(mod, "+")} {k(mod, "-")} {k(mod, "0")}</td><td>Zoom in / out / reset</td></tr>
<tr><td>{k(mod, "P")}</td><td>Print</td></tr>
<tr><td>{k(mod, sh, "S")}</td><td>Security panel</td></tr>
<tr><td>{k(mod, sh, "F")}</td><td>Add finding</td></tr>
<tr><td>{k(mod, alt, "N")}</td><td>New Tor window</td></tr>
<tr><td>{k(mod, ",")}</td><td>Settings</td></tr>
<tr><td>{k("F12")} · {k(mod, "U")}</td><td>Developer tools · view source</td></tr>
<tr><td>{k("F11")}</td><td>Full screen</td></tr>
<tr><td>{k("F1")}</td><td>This guide</td></tr>
<tr><td>{k(mod, sh, "Delete")}</td><td>Clear search &amp; address history</td></tr>
</table>"""),
        ("trouble", "Install, updates &amp; troubleshooting", """
<ul>
<li><b>Updates</b>: Wyrm checks quietly at startup and every few hours. When a new version is out, a blue
<b>Update</b> button appears at the top right of the toolbar — click it to download and install. You can also use
⋮ → <b>Check for updates…</b> any time.</li>
<li><b>A site doesn't work</b>: turn off <i>Shields up for this site</i> in Security panel → Shields, then reload.</li>
<li><b>No news on the start page</b>: you are offline, or the news sites could not be reached — it appears automatically when you reconnect.</li>
<li><b>macOS says “damaged” or “can't be verified”</b> after installing: open Terminal and run the command below,
or go to System Settings → Privacy &amp; Security → <b>Open Anyway</b>.</li>
</ul>
<pre>xattr -dr com.apple.quarantine /Applications/Wyrm.app</pre>
<ul><li><b>Windows SmartScreen</b>: click <b>More info → Run anyway</b>. Wyrm is not yet signed with a paid certificate.</li></ul>"""),
    ]
    nav = "<b>ON THIS PAGE</b>" + "".join(f"<a href='#{sid}'>{title}</a>" for sid, title, _ in sections)
    body = "".join(f"<section id='{sid}'><h2>{title}</h2>{html}</section>" for sid, title, html in sections)
    content = (f"<nav>{nav}</nav><div><h1>How to use Wyrm</h1>"
               "<p class='lead'>A quick guide to browsing privately and testing safely. "
               f"Open it any time from ⋮ → <b>Help — how to use Wyrm</b> or with {k('F1')}.</p>"
               f"{body}<p class='top'><a href='#start'>Back to top</a> · <a href='wyrm://home'>Start page</a></p>"
               "<p class='top'>Wyrm is made by <b>ByKh R&amp;D Group</b> — <a href='https://bykh.org'>bykh.org</a>"
               " · with <b>HackPi</b>, Ethical Hackers Group.</p></div>")
    return _page("How to use Wyrm", content, HELP_CSS, "help")
