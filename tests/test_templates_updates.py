#------------------------------------------------------------------------------
# Wyrm — tests/test_templates_updates.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""B3 + speed-ups: template paths are normalized when packaging (no look-alike "‎http" folder), only a
complete updated template set is used, katana/nuclei run with the faster presets, and updates can be frozen."""
import io
import sys
import tarfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

pytest.importorskip("requests")
import fetch_pdtools  # noqa: E402
from wyrm import updater  # noqa: E402
from wyrm.security import pdtools  # noqa: E402

LRM = "‎"


def test_clean_member_path():
    assert fetch_pdtools.clean_member_path(LRM + "http/technologies/x.yaml") == "http/technologies/x.yaml"
    assert fetch_pdtools.clean_member_path("http/﻿a.yaml") == "http/a.yaml"
    assert fetch_pdtools.clean_member_path("http/../../etc/passwd") is None
    assert fetch_pdtools.clean_member_path("http/руткит.yaml") is None          # other non-ASCII: rejected
    assert fetch_pdtools.clean_member_path("cloud/aws/s3.yaml") == "cloud/aws/s3.yaml"


def _tarball(files: dict) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, body in files.items():
            data = body.encode()
            ti = tarfile.TarInfo("nuclei-templates-v10.0.0/" + name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def test_extract_merges_lookalike_folder(tmp_path):
    data = _tarball({"http/cves/a.yaml": "a", LRM + "http/technologies/luaniaoagent-detect.yaml": "b",
                     "http/evilа.yaml": "c"})
    n, skipped = fetch_pdtools.extract_templates(data, tmp_path)
    assert n == 2 and skipped == ["http/evilа.yaml"]
    assert (tmp_path / "http" / "technologies" / "luaniaoagent-detect.yaml").is_file()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["http"]            # one http folder only


def _set(d: Path, n: int, checksum=True):
    d.mkdir(parents=True, exist_ok=True)
    for i in range(n):
        (d / f"t{i}.yaml").write_text("x")
    if checksum:
        (d / ".checksum").write_text("x")
    return d


def test_only_a_complete_updated_set_is_used(tmp_path, monkeypatch):
    monkeypatch.setattr(pdtools, "MIN_TEMPLATES", 10)
    assert not pdtools.updated_templates_valid(_set(tmp_path / "a", 50, checksum=False), 50)   # unfinished
    assert not pdtools.updated_templates_valid(_set(tmp_path / "b", 5), 50)                     # tiny
    assert not pdtools.updated_templates_valid(_set(tmp_path / "c", 40), 50)                    # < 90 %
    assert pdtools.updated_templates_valid(_set(tmp_path / "d", 48), 50)
    monkeypatch.setattr(pdtools, "USER_DIR", tmp_path / "user")
    monkeypatch.setattr(pdtools, "BUNDLED", tmp_path / "bundle")
    _set(tmp_path / "bundle" / "nuclei-templates", 50)
    pdtools._TPL_CACHE.clear()
    assert pdtools.templates_dir() == tmp_path / "bundle" / "nuclei-templates"   # no update yet
    _set(tmp_path / "user" / "nuclei-templates", 49)
    pdtools._TPL_CACHE.clear()
    assert pdtools.templates_dir() == tmp_path / "user" / "nuclei-templates"     # valid update preferred


def test_fast_presets():
    k = pdtools.TOOLS_BY_KEY["katana"].args
    for flag in ("-jsl", "-c", "-p", "-timeout"):
        assert flag in k
    assert k[k.index("-c") + 1] == "10" and k[k.index("-p") + 1] == "10" and k[k.index("-timeout") + 1] == "5"
    default = pdtools.TOOLS_BY_KEY["nuclei"].args                               # fast preset, same lab findings
    assert "-tags" in default and "exposure" in default[default.index("-tags") + 1]
    auto = pdtools.TOOLS_BY_KEY["nuclei-auto"]
    assert "-as" in auto.args and auto.binary == "nuclei" and auto.active
    full = pdtools.TOOLS_BY_KEY["nuclei-full"]
    assert "-as" not in full.args and full.binary == "nuclei" and full.active


def test_freeze_updates(monkeypatch):
    class S:
        def __init__(self, v):
            self.v = v

        def value(self, k, d=None, type=None):  # noqa: A002
            return self.v if k == "updates/freeze" else d
    monkeypatch.delenv("WYRM_NO_UPDATE", raising=False)
    assert not updater.updates_frozen(S(False)) and updater.updates_frozen(S("true"))
    monkeypatch.setenv("WYRM_NO_UPDATE", "1")
    assert updater.updates_frozen(S(False)) and updater.updates_frozen(None)
