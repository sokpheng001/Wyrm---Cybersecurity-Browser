"""Export an engagement's findings as Markdown or a self-contained HTML report."""
from __future__ import annotations

import base64
from datetime import datetime
from html import escape

from .store import SEVERITIES, Engagement

COLORS = {"critical": "#7b1fa2", "high": "#d93025", "medium": "#e8710a", "low": "#f9ab00", "info": "#5f6368"}


def to_markdown(e: Engagement, findings: list[dict]) -> str:
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    lines = [f"# Security assessment: {e.name}", "",
             f"*Generated {datetime.now():%Y-%m-%d %H:%M} with Wyrm · ByKh R&D Group · HackPi — Ethical Hackers Group*", "",
             "## Scope", ""] + [f"- `{s}`" for s in e.scope] + ["", "## Summary", "",
             "| Severity | Count |", "|---|---|"] + [f"| {s.title()} | {counts[s]} |" for s in SEVERITIES]
    if e.notes:
        lines += ["", "## Notes", "", e.notes]
    lines += ["", "## Findings", ""]
    for i, f in enumerate(findings, 1):
        lines += [f"### {i}. {f['title']}", "", f"**Severity:** {f['severity'].title()}  ",
                  f"**URL:** {f['url'] or '-'}  ", f"**Found:** {f['created']}", ""]
        if f.get("description"):
            lines += [f["description"], ""]
        if f.get("evidence"):
            lines += ["**Evidence**", "", "```", f["evidence"], "```", ""]
        if f.get("screenshot"):
            lines += ["*(screenshot included in the HTML report)*", ""]
    return "\n".join(lines)


def to_html(e: Engagement, findings: list[dict]) -> str:
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    chips = "".join(f"<span class='chip' style='background:{COLORS[s]}'>{counts[s]} {s.title()}</span>"
                    for s in SEVERITIES)
    rows = "".join(
        f"<tr><td>{i}</td><td><a href='#f{i}'>{escape(f['title'])}</a></td>"
        f"<td><span class='sev' style='background:{COLORS.get(f['severity'], '#555')}'>{f['severity'].title()}</span></td></tr>"
        for i, f in enumerate(findings, 1))
    body = []
    for i, f in enumerate(findings, 1):
        img = ""
        if f.get("screenshot"):
            img = f"<img alt='screenshot' src='data:image/png;base64,{base64.b64encode(f['screenshot']).decode()}'>"
        ev = f"<h4>Evidence</h4><pre>{escape(f['evidence'])}</pre>" if f.get("evidence") else ""
        desc = f"<p>{escape(f['description']).replace(chr(10), '<br>')}</p>" if f.get("description") else ""
        body.append(
            f"<section id='f{i}'><h3>{i}. {escape(f['title'])} "
            f"<span class='sev' style='background:{COLORS.get(f['severity'], '#555')}'>{f['severity'].title()}</span></h3>"
            f"<p class='meta'>{escape(f['url'] or '')} · {escape(f['created'] or '')}</p>{desc}{ev}{img}</section>")
    scope = "".join(f"<li><code>{escape(s)}</code></li>" for s in e.scope)
    notes = f"<h2>Notes</h2><p>{escape(e.notes)}</p>" if e.notes else ""
    return f"""<!doctype html><html><head><meta charset='utf-8'><title>{escape(e.name)}: security report</title>
<style>
body{{font:15px/1.55 system-ui,'Segoe UI',sans-serif;color:#202124;max-width:900px;margin:40px auto;padding:0 20px}}
h1{{margin-bottom:4px}} .meta{{color:#5f6368;font-size:13px}} code,pre{{font-family:Consolas,ui-monospace,monospace}}
pre{{background:#f6f8fa;border:1px solid #e1e4e8;border-radius:8px;padding:12px;overflow:auto;font-size:13px;white-space:pre-wrap}}
.chip,.sev{{display:inline-block;color:#fff;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;margin-right:6px}}
table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid #eee;padding:8px;text-align:left}}
section{{border-top:1px solid #eee;margin-top:28px;padding-top:8px}} img{{max-width:100%;border:1px solid #ddd;border-radius:8px}}
</style></head><body>
<h1>Security assessment: {escape(e.name)}</h1>
<p class='meta'>Generated {datetime.now():%Y-%m-%d %H:%M} with Wyrm · ByKh R&amp;D Group · HackPi — Ethical Hackers Group</p>
<h2>Summary</h2><p>{chips}</p><table><tr><th>#</th><th>Finding</th><th>Severity</th></tr>{rows}</table>
<h2>Scope</h2><ul>{scope}</ul>{notes}<h2>Findings</h2>{''.join(body) or '<p>No findings recorded.</p>'}
</body></html>"""
