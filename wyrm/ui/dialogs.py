#------------------------------------------------------------------------------
# Wyrm — wyrm/ui/dialogs.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Wyrm's own question dialog (title, text, optional checkbox, buttons on the right).

Used instead of QMessageBox, which squeezes its text into a narrow column. Styled by theme.py
(QDialog#ConfirmDialog, QLabel#DialogTitle / #DialogBody, QPushButton#Primary).
"""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QDialog, QHBoxLayout, QLabel, QPushButton, QVBoxLayout, QWidget


def ask(parent: QWidget, title: str, body: str, ok: str, cancel: str = "Cancel",
        checkbox: str | None = None, window_title: str = "Wyrm Browser") -> tuple[bool, bool]:
    """Show the dialog. Returns (accepted, checkbox ticked). The OK button is the default (Enter)."""
    d = QDialog(parent, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
    d.setObjectName("ConfirmDialog")
    d.setWindowTitle(window_title)
    d.setMinimumWidth(460)
    v = QVBoxLayout(d)
    v.setContentsMargins(28, 24, 28, 22)
    v.setSpacing(12)
    head = QLabel(title)
    head.setObjectName("DialogTitle")
    head.setWordWrap(True)
    v.addWidget(head)
    text = QLabel(body)
    text.setObjectName("DialogBody")
    text.setWordWrap(True)
    v.addWidget(text)
    box = None
    if checkbox:
        v.addSpacing(4)
        box = QCheckBox(checkbox)
        v.addWidget(box)
    v.addSpacing(6)
    row = QHBoxLayout()
    row.setSpacing(8)
    row.addStretch(1)
    no, yes = QPushButton(cancel), QPushButton(ok)
    yes.setObjectName("Primary")
    yes.setDefault(True)
    for b in (no, yes):
        b.setMinimumWidth(110)
    no.clicked.connect(d.reject)
    yes.clicked.connect(d.accept)
    row.addWidget(no)
    row.addWidget(yes)
    v.addLayout(row)
    accepted = d.exec() == QDialog.DialogCode.Accepted
    return accepted, bool(box and box.isChecked())


_LEVELS = {  # banner colour, banner text colour, label
    "danger": ("#da1e28", "#ffffff", "Dangerous"),
    "caution": ("#f1c21b", "#161616", "Be careful"),
}


def security_warning(parent: QWidget, level: str, title: str, body: str, risks: list[str] | None = None,
                     proceed: str = "Continue anyway", back: str = "Back to safety") -> bool:
    """Wyrm Shield warning (like Avast Secure Browser's): coloured banner with a shield, what happened, the
    specific risks, and two buttons. The SAFE choice is the default (Enter/Esc never proceed); proceeding is the
    secondary button. Returns True only if the user explicitly chose to proceed."""
    from html import escape
    from PySide6.QtWidgets import QFrame
    bg, fg, tag = _LEVELS.get(level, _LEVELS["caution"])
    d = QDialog(parent, Qt.WindowType.Dialog | Qt.WindowType.FramelessWindowHint)
    d.setObjectName("ConfirmDialog")
    d.setWindowTitle("Wyrm Shield")
    d.setMinimumWidth(500)
    outer = QVBoxLayout(d)
    outer.setContentsMargins(0, 0, 0, 0)
    outer.setSpacing(0)
    band = QFrame()
    band.setStyleSheet(f"QFrame {{ background: {bg}; }} QLabel {{ color: {fg}; background: transparent; }}")
    bl = QHBoxLayout(band)
    bl.setContentsMargins(24, 14, 24, 14)
    shield = QLabel("\U0001F6E1")  # shield
    shield.setStyleSheet("font-size: 26px;")
    bl.addWidget(shield)
    bl.addSpacing(6)
    lab = QLabel(f"<b style='font-size:15px'>Wyrm Shield</b><br><span style='font-size:12px'>{tag}</span>")
    bl.addWidget(lab, 1)
    outer.addWidget(band)
    v = QVBoxLayout()
    v.setContentsMargins(28, 20, 28, 22)
    v.setSpacing(12)
    head = QLabel(title)
    head.setObjectName("DialogTitle")
    head.setWordWrap(True)
    v.addWidget(head)
    text = QLabel(body)
    text.setObjectName("DialogBody")
    text.setWordWrap(True)
    text.setTextFormat(Qt.TextFormat.RichText)
    v.addWidget(text)
    if risks:
        lst = QLabel("<ul style='margin:0 0 0 -16px'>" + "".join(f"<li>{escape(r)}</li>" for r in risks) + "</ul>")
        lst.setObjectName("DialogBody")
        lst.setWordWrap(True)
        v.addWidget(lst)
    v.addSpacing(6)
    row = QHBoxLayout()
    row.setSpacing(8)
    row.addStretch(1)
    go, safe = QPushButton(proceed), QPushButton(back)
    safe.setObjectName("Primary")
    safe.setDefault(True)
    safe.setAutoDefault(True)
    go.setAutoDefault(False)
    for b in (go, safe):
        b.setMinimumWidth(130)
    go.clicked.connect(d.accept)
    safe.clicked.connect(d.reject)
    row.addWidget(go)
    row.addWidget(safe)
    v.addLayout(row)
    outer.addLayout(v)
    safe.setFocus()
    return d.exec() == QDialog.DialogCode.Accepted
