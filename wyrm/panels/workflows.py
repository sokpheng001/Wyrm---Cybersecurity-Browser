#------------------------------------------------------------------------------
# Wyrm — wyrm/panels/workflows.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Workflows tab: build Caido-style automation pipelines that run on live proxy traffic."""
from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QComboBox, QGroupBox, QHBoxLayout, QLabel, QLineEdit, QPushButton, QTreeWidget,
                               QTreeWidgetItem, QVBoxLayout, QWidget)

from ..security import mitm, workflows


def _step_detail(step: dict) -> str:
    t = step.get("type")
    if t == "set-header":
        return f"{step.get('name','')}: {step.get('value','')}"
    if t == "remove-header":
        return step.get("name", "")
    if t == "replace":
        return f"[{step.get('part','body')}] /{step.get('find','')}/ → {step.get('repl','')}"
    if t == "set-status":
        return str(step.get("value", ""))
    return ""


class WorkflowsTab(QWidget):
    """Create/edit automation pipelines; the WorkflowEngine applies them inside the proxy."""

    _hit = Signal(str)

    def __init__(self, win):
        super().__init__()
        self.win = win
        self.engine = workflows.WorkflowEngine().load(win.data_dir / "workflows.json")
        self.engine.notify = lambda name: self._hit.emit(name)
        self._hit.connect(lambda _n: self._refresh_list(keep=True))
        if mitm.ACTIVE is not None:
            self.engine.install(mitm.ACTIVE)

        v = QVBoxLayout(self)
        active = mitm.ACTIVE is not None
        intro = QLabel(
            "<b>Workflows</b> — automation pipelines that rewrite live traffic through the proxy: set or strip "
            "headers, find/replace in bodies, force a status. They apply to HTTPS too." + (
                "" if active else " <br><i>Turn on the intercepting proxy (Proxy tab) for workflows to run.</i>"))
        intro.setWordWrap(True)
        v.addWidget(intro)

        top = QHBoxLayout()
        b_new = QPushButton("New workflow")
        b_new.clicked.connect(self._new)
        top.addWidget(b_new)
        self.b_del = QPushButton("Delete")
        self.b_del.clicked.connect(self._delete)
        top.addWidget(self.b_del)
        top.addStretch(1)
        v.addLayout(top)

        self.list = QTreeWidget()
        self.list.setHeaderLabels(["On", "Workflow", "Scope", "Hits"])
        self.list.setRootIsDecorated(False)
        self.list.setColumnWidth(0, 34)
        self.list.setColumnWidth(1, 150)
        self.list.setMaximumHeight(150)
        self.list.currentItemChanged.connect(lambda *_: self._load_selected())
        self.list.itemChanged.connect(self._item_changed)
        v.addWidget(self.list)

        self.editor = QGroupBox("Selected workflow")
        eg = QVBoxLayout(self.editor)
        name_row = QHBoxLayout()
        name_row.addWidget(QLabel("Name"))
        self.name = QLineEdit()
        self.name.editingFinished.connect(self._save_meta)
        name_row.addWidget(self.name, 1)
        eg.addLayout(name_row)
        scope_row = QHBoxLayout()
        scope_row.addWidget(QLabel("Scope"))
        self.scope = QLineEdit()
        self.scope.setPlaceholderText("URL contains… (blank = all traffic)")
        self.scope.editingFinished.connect(self._save_meta)
        scope_row.addWidget(self.scope, 1)
        eg.addLayout(scope_row)

        self.steps = QTreeWidget()
        self.steps.setHeaderLabels(["Where", "Step", "Detail"])
        self.steps.setRootIsDecorated(False)
        self.steps.setColumnWidth(0, 50)
        self.steps.setColumnWidth(1, 110)
        self.steps.setMaximumHeight(150)
        eg.addWidget(self.steps)

        # add-step form
        f1 = QHBoxLayout()
        self.where = QComboBox()
        self.where.addItems(["req", "resp"])
        f1.addWidget(self.where)
        self.type = QComboBox()
        self.type.addItems(list(workflows.STEP_TYPES))
        self.type.currentTextChanged.connect(self._sync_fields)
        f1.addWidget(self.type, 1)
        eg.addLayout(f1)
        f2 = QHBoxLayout()
        self.part = QComboBox()
        self.part.addItems(["body", "header"])
        f2.addWidget(self.part)
        self.a = QLineEdit()      # name / find
        f2.addWidget(self.a, 1)
        self.b = QLineEdit()      # value / repl
        f2.addWidget(self.b, 1)
        eg.addLayout(f2)
        f3 = QHBoxLayout()
        b_add = QPushButton("Add step")
        b_add.clicked.connect(self._add_step)
        f3.addWidget(b_add)
        b_rm = QPushButton("Remove step")
        b_rm.clicked.connect(self._remove_step)
        f3.addWidget(b_rm)
        f3.addStretch(1)
        eg.addLayout(f3)
        v.addWidget(self.editor)
        v.addStretch(1)

        self._sync_fields()
        self._refresh_list()
        self.editor.setEnabled(False)

    # -------------------------------------------------- workflow list
    def _refresh_list(self, keep=False):
        cur = self.list.currentItem()
        cur_name = cur.data(1, Qt.ItemDataRole.UserRole) if cur else None
        self.list.blockSignals(True)
        self.list.clear()
        for wf in self.engine.workflows:
            it = QTreeWidgetItem(["", wf.get("name", ""), wf.get("scope", ""), str(wf.get("hits", 0))])
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(0, Qt.CheckState.Checked if wf.get("enabled", True) else Qt.CheckState.Unchecked)
            it.setData(1, Qt.ItemDataRole.UserRole, id(wf))
            self.list.addTopLevelItem(it)
            if keep and cur_name == id(wf):
                self.list.setCurrentItem(it)
        self.list.blockSignals(False)

    def _selected_wf(self):
        it = self.list.currentItem()
        if not it:
            return None
        wid = it.data(1, Qt.ItemDataRole.UserRole)
        return next((wf for wf in self.engine.workflows if id(wf) == wid), None)

    def _item_changed(self, it, col):
        if col != 0:
            return
        wid = it.data(1, Qt.ItemDataRole.UserRole)
        wf = next((w for w in self.engine.workflows if id(w) == wid), None)
        if wf is not None:
            wf["enabled"] = it.checkState(0) == Qt.CheckState.Checked
            self.engine.save()

    def _new(self):
        wf = {"name": f"Workflow {len(self.engine.workflows) + 1}", "enabled": True, "scope": "",
              "steps": [], "hits": 0}
        self.engine.workflows.append(wf)
        self.engine.save()
        self._refresh_list()
        self.list.setCurrentItem(self.list.topLevelItem(self.list.topLevelItemCount() - 1))

    def _delete(self):
        wf = self._selected_wf()
        if wf is None:
            return
        self.engine.workflows.remove(wf)
        self.engine.save()
        self._refresh_list()
        self._load_selected()

    # -------------------------------------------------- selected workflow editor
    def _load_selected(self):
        wf = self._selected_wf()
        self.editor.setEnabled(wf is not None)
        if wf is None:
            self.name.clear()
            self.scope.clear()
            self.steps.clear()
            return
        self.name.setText(wf.get("name", ""))
        self.scope.setText(wf.get("scope", ""))
        self.steps.clear()
        for step in wf.get("steps", []):
            self.steps.addTopLevelItem(QTreeWidgetItem([step.get("where", "req"), step.get("type", ""),
                                                        _step_detail(step)]))

    def _save_meta(self):
        wf = self._selected_wf()
        if wf is None:
            return
        wf["name"] = self.name.text().strip() or wf["name"]
        wf["scope"] = self.scope.text().strip()
        self.engine.save()
        self._refresh_list(keep=True)

    def _sync_fields(self):
        t = self.type.currentText()
        self.part.setVisible(t == "replace")
        self.a.setVisible(t in ("set-header", "remove-header", "replace"))
        self.b.setVisible(t in ("set-header", "replace", "set-status"))
        self.a.setPlaceholderText("find (regex)" if t == "replace" else "header name")
        self.b.setPlaceholderText({"replace": "replacement", "set-status": "status code"}.get(t, "header value"))

    def _add_step(self):
        wf = self._selected_wf()
        if wf is None:
            return
        t = self.type.currentText()
        step = {"type": t, "where": self.where.currentText()}
        if t == "set-header":
            if not self.a.text().strip():
                return
            step["name"] = self.a.text().strip()
            step["value"] = self.b.text()
        elif t == "remove-header":
            if not self.a.text().strip():
                return
            step["name"] = self.a.text().strip()
        elif t == "replace":
            if not self.a.text():
                return
            step["part"] = self.part.currentText()
            step["find"] = self.a.text()
            step["repl"] = self.b.text()
        elif t == "set-status":
            step["where"] = "resp"
            step["value"] = self.b.text().strip()
        wf.setdefault("steps", []).append(step)
        self.engine.save()
        self._load_selected()
        self.a.clear()
        self.b.clear()

    def _remove_step(self):
        wf = self._selected_wf()
        idx = self.steps.indexOfTopLevelItem(self.steps.currentItem()) if self.steps.currentItem() else -1
        if wf is None or idx < 0:
            return
        del wf["steps"][idx]
        self.engine.save()
        self._load_selected()
