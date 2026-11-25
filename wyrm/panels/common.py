#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/common.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Shared helpers for the Security panel tabs (highlighting, badges, panes, sorting)."""
from __future__ import annotations

import re
from html import escape
from pathlib import Path

from PySide6.QtGui import QColor
from PySide6.QtWidgets import QHBoxLayout, QLabel, QTreeWidgetItem, QVBoxLayout, QWidget

from .. import theme


SEV_COLOR = theme.SEVERITY


# pageinfo.js with the per-session hook token filled in (B2); empty if a build is missing the file
from ..browser.scripts import PAGEINFO_JS  # noqa: E402


def mono(widget):
    f = widget.font()
    f.setFamilies([theme.MONO, "Consolas", "monospace"])
    widget.setFont(f)
    return widget


class HeaderHighlighter:
    """Colors 'Header-Name:' vs value in an editable request-headers box (keeps it editable)."""

    def __new__(cls, editor):
        from PySide6.QtCore import QRegularExpression
        from PySide6.QtGui import QColor, QSyntaxHighlighter, QTextCharFormat

        class _HL(QSyntaxHighlighter):
            def __init__(self, doc):
                super().__init__(doc)
                self.name_fmt = QTextCharFormat()
                self.name_fmt.setForeground(QColor("#8d8d8d"))
                self.name_fmt.setFontWeight(600)
                self.re = QRegularExpression(r"^([A-Za-z0-9!#$%&'*+.^_`|~-]+)\s*:")

            def highlightBlock(self, text):
                m = self.re.match(text)
                if m.hasMatch():
                    self.setFormat(0, m.capturedEnd(1), self.name_fmt)
        return _HL(editor.document())


# syntax-highlight colors (readable on both light and dark response backgrounds)
_HL = {"key": "#0f62fe", "str": "#24a148", "num": "#ff832b", "kw": "#8a3ffc", "pun": "#8d8d8d",
       "tag": "#0f62fe", "com": "#8d8d8d", "hdr": "#8a3ffc"}


_JSON_TOK = re.compile(r'"(?:\\.|[^"\\])*"|\b(?:true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|[{}\[\],:]|\s+|[^"{}\[\],:\s]+')


_MARKUP_TOK = re.compile(r'<!--.*?-->|</?[^>]+>', re.S)


_GEN_TOK = re.compile(
    r'("(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\')|(\b\d+(?:\.\d+)?\b)'
    r'|(\b(?:function|return|var|let|const|if|else|for|while|true|false|null|undefined|new|class|import|export|async|await)\b)')


def _span(color: str, text: str) -> str:
    return f"<span style='color:{color}'>{escape(text)}</span>"


def _hl_json(text: str) -> str:
    out = []
    for m in _JSON_TOK.finditer(text):
        t = m.group(0)
        if t.isspace():
            out.append(escape(t))
        elif t[0] == '"':
            out.append(_span(_HL["key"] if text[m.end():].lstrip().startswith(":") else _HL["str"], t))
        elif t in ("true", "false", "null"):
            out.append(_span(_HL["kw"], t))
        elif t[0] == "-" or t[0].isdigit():
            out.append(_span(_HL["num"], t))
        elif t in "{}[],:":
            out.append(_span(_HL["pun"], t))
        else:
            out.append(escape(t))
    return "".join(out)


def _hl_markup(text: str) -> str:
    out, pos = [], 0
    for m in _MARKUP_TOK.finditer(text):
        out.append(escape(text[pos:m.start()]))
        seg = m.group(0)
        out.append(_span(_HL["com"] if seg.startswith("<!--") else _HL["tag"], seg))
        pos = m.end()
    out.append(escape(text[pos:]))
    return "".join(out)


def _hl_generic(text: str) -> str:
    out, pos = [], 0
    for m in _GEN_TOK.finditer(text):
        out.append(escape(text[pos:m.start()]))
        c = _HL["str"] if m.group(1) else _HL["num"] if m.group(2) else _HL["kw"]
        out.append(_span(c, m.group(0)))
        pos = m.end()
    out.append(escape(text[pos:]))
    return "".join(out)


def _highlight_body(body: str, ctype: str) -> str:
    if len(body) > 400_000:          # keep very large bodies responsive — skip highlighting
        return escape(body)
    b = body.lstrip()
    if "json" in ctype or b[:1] in "{[":
        return _hl_json(body)
    if "html" in ctype or "xml" in ctype or b[:1] == "<":
        return _hl_markup(body)
    return _hl_generic(body)


def _format_response(r: dict) -> str:
    """Render an HTTP response as clean, syntax-highlighted HTML: status line, headers, body."""
    head = r.get("head", "")
    lines = head.split("\n")
    status_line = lines[0] if lines else ""
    status = r.get("status") or 0
    color = {2: "#24a148", 3: "#4589ff", 4: "#ff832b", 5: "#da1e28"}.get(status // 100, "#8d8d8d")
    out = [f"<div style='font-weight:600;color:{color};margin-bottom:6px'>{escape(status_line)}</div>"]
    hdr, ctype = [], ""
    for ln in lines[1:]:
        if ": " in ln:
            name, val = ln.split(": ", 1)
            if name.lower() == "content-type":
                ctype = val.lower()
            hdr.append(f"<span style='color:{_HL['hdr']};font-weight:600'>{escape(name)}:</span> {escape(val)}")
        elif ln.strip():
            hdr.append(escape(ln))
    if hdr:
        out.append("<div style='line-height:1.5'>" + "<br>".join(hdr) + "</div>")
    body = r.get("body", "")
    if body:
        out.append("<hr style='border:none;border-top:1px solid #8884;margin:8px 0'>")
        out.append(f"<pre style='white-space:pre-wrap;margin:0'>{_highlight_body(body, ctype)}</pre>")
    return "".join(out)


def sev_badge(sev: str) -> str:
    fg = "#161616" if sev == "medium" else "#ffffff"  # Carbon yellow needs dark text
    return (f"<span style='background:{SEV_COLOR.get(sev, '#8d8d8d')};color:{fg};"
            f"font-weight:600'>&nbsp;{sev.title()}&nbsp;</span>")


class _SortItem(QTreeWidgetItem):
    """Tree item that sorts numeric columns numerically (for the Intruder results table)."""

    def __lt__(self, other):
        col = self.treeWidget().sortColumn() if self.treeWidget() else 0
        a, b = self.text(col), other.text(col)
        try:
            return float(a) < float(b)
        except ValueError:
            return a < b


def _pane(title, widget, extra=None):
    """Labelled editor section used in stacked splitters (Repeater, Intruder, …). Consistent rhythm:
    12px above every section label, 6px between the label and its editor."""
    box = QWidget()
    bl = QVBoxLayout(box)
    bl.setContentsMargins(0, 12, 0, 0)
    bl.setSpacing(6)
    head = QHBoxLayout()
    lab = QLabel(title)
    lab.setObjectName("PaneLabel")
    head.addWidget(lab)
    head.addStretch(1)
    if extra:
        extra(head)
    bl.addLayout(head)
    bl.addWidget(widget, 1)
    return box


STATUS_COLOR = {2: "#1e8e3e", 3: "#4589ff", 4: "#fa7b17", 5: "#da1e28"}
