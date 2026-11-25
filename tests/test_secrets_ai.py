#------------------------------------------------------------------------------
# Wyrm — tests/test_secrets_ai.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""F4: the AI Triage key lives in the OS keyring, is migrated out of QSettings, and is never written to disk in
plain text when no keyring exists. F5: placeholder model reset, clear error messages, connection test.
No network: HTTP calls are stubbed. Run: `python -m pytest tests/test_secrets_ai.py`."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from wyrm import secretstore  # noqa: E402
from wyrm.security import triage  # noqa: E402


class FakeSettings:
    def __init__(self, **kv):
        self.d = dict(kv)

    def value(self, key, default=None, type=None):  # noqa: A002
        return self.d.get(key, default)

    def setValue(self, key, val):  # noqa: N802
        self.d[key] = val

    def remove(self, key):
        self.d.pop(key, None)


class FakeKeyring:
    def __init__(self):
        self.store = {}

    def set_password(self, svc, user, pw):
        self.store[(svc, user)] = pw

    def get_password(self, svc, user):
        return self.store.get((svc, user))

    def delete_password(self, svc, user):
        self.store.pop((svc, user))


@pytest.fixture
def kr(monkeypatch):
    k = FakeKeyring()
    monkeypatch.setattr(secretstore, "_backend_override", k)
    monkeypatch.setattr(secretstore, "_session", {})
    return k


@pytest.fixture
def no_kr(monkeypatch):
    monkeypatch.setattr(secretstore, "_keyring", lambda: None)
    monkeypatch.setattr(secretstore, "_session", {})


def test_saved_key_goes_to_keyring_not_settings(kr):
    s = FakeSettings()
    secretstore.set(s, "ai/api_key", "  sk-ant-test-123 ")
    assert "ai/api_key" not in s.d
    assert kr.store[("Wyrm", "ai_api_key")] == "sk-ant-test-123"
    assert secretstore.get(s, "ai/api_key") == "sk-ant-test-123"
    secretstore.set(s, "ai/api_key", "")             # clearing deletes it
    assert ("Wyrm", "ai_api_key") not in kr.store and secretstore.get(s, "ai/api_key") == ""


def test_plaintext_setting_is_migrated_and_deleted(kr):
    s = FakeSettings(**{"ai/api_key": "sk-ant-legacy", "other": 1})
    assert secretstore.migrate(s) == ["ai/api_key"]
    assert "ai/api_key" not in s.d and s.d["other"] == 1
    assert kr.store[("Wyrm", "ai_api_key")] == "sk-ant-legacy"
    assert secretstore.migrate(s) == []              # idempotent


def test_no_keyring_never_writes_plaintext(no_kr):
    s = FakeSettings(**{"ai/api_key": "sk-ant-legacy"})
    secretstore.migrate(s)
    assert "ai/api_key" not in s.d                   # plain copy removed from disk…
    assert secretstore.get(s, "ai/api_key") == "sk-ant-legacy"   # …but usable this session
    secretstore.set(s, "ai/api_key", "sk-new")
    assert "ai/api_key" not in s.d and secretstore.get(s, "ai/api_key") == "sk-new"
    ok, text = secretstore.keyring_status()
    assert ok is False and "until Wyrm quits" in text


def test_placeholder_model_is_reset():
    s = FakeSettings(**{"ai/model": "kim-modeling-sp-001"})
    assert triage.migrate_model_setting(s) is True and s.d["ai/model"] == ""
    s = FakeSettings(**{"ai/model": "claude-opus-5-5"})
    assert triage.migrate_model_setting(s) is False and s.d["ai/model"] == "claude-opus-5-5"
    assert triage.model_looks_valid(triage.DEFAULT_MODEL)
    assert not triage.model_looks_valid("kim-modeling-sp-001")


class FakeResp:
    def __init__(self, status, body):
        self.status_code, self._body = status, body
        self.text = json.dumps(body) if not isinstance(body, str) else body

    def json(self):
        if isinstance(self._body, str):
            raise ValueError
        return self._body


@pytest.mark.parametrize("status,etype,needle", [
    (401, "authentication_error", "API key was rejected"),
    (404, "not_found_error", "unknown model"),
    (429, "rate_limit_error", "rate limited"),
    (529, "overloaded_error", "overloaded"),
])
def test_http_errors_are_clear(monkeypatch, status, etype, needle):
    body = {"type": "error", "error": {"type": etype, "message": "boom"}}
    monkeypatch.setattr(triage.requests, "post", lambda *a, **k: FakeResp(status, body))
    with pytest.raises(triage.TriageError) as ei:
        triage.triage("GET / HTTP/1.1", "127.0.0.1", "k")
    assert ei.value.status == status and needle in str(ei.value) and etype in str(ei.value)


def test_unreachable_endpoint(monkeypatch):
    def boom(*a, **k):
        raise triage.requests.ConnectionError("down")
    monkeypatch.setattr(triage.requests, "post", boom)
    with pytest.raises(triage.TriageError) as ei:
        triage.test_connection("k")
    assert ei.value.status == 0 and "can't reach" in str(ei.value)


def test_bad_model_rejected_before_network(monkeypatch):
    monkeypatch.setattr(triage.requests, "post", lambda *a, **k: pytest.fail("should not call the API"))
    with pytest.raises(triage.TriageError):
        triage.triage("x", "", "k", model="kim-modeling-sp-001")


def test_success_and_refusal(monkeypatch):
    ok = {"model": "claude-sonnet-5-5", "stop_reason": "end_turn", "content": [{"type": "text", "text": "OK"}]}
    monkeypatch.setattr(triage.requests, "post", lambda *a, **k: FakeResp(200, ok))
    assert "Connected" in triage.test_connection("k")
    assert triage.triage("x", "", "k") == "OK"
    ref = {"stop_reason": "refusal", "stop_details": {"explanation": "policy"}, "content": []}
    monkeypatch.setattr(triage.requests, "post", lambda *a, **k: FakeResp(200, ref))
    assert "declined" in triage.triage("x", "", "k")
