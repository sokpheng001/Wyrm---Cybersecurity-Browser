#------------------------------------------------------------------------------
# Wyrm — wyrm/security/triage.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""AI Triage: a scope-gated, human-in-the-loop, non-destructive AppSec analysis assistant.

It sends a request/response pair, API schema, or source code to an LLM (the user's own API key) and
returns structured findings + SAFE manual verification steps + remediation. It never sends network
requests itself and only ever proposes benign canary checks — the operating rules are baked into the
system prompt below.
"""
from __future__ import annotations

import json
import re

import requests

API_URL = "https://api.anthropic.com/v1/messages"
# A real, current Claude model id (BUG-2): the previous default was a placeholder dev string that made every
# Triage call fail with a model error until the user overwrote it. Users can still override in Settings → Model.
DEFAULT_MODEL = "claude-sonnet-5-5"
# F5: ids that only ever worked against an internal dev endpoint; a stored copy is reset to DEFAULT_MODEL.
_PLACEHOLDER_MODELS = {"kim-modeling-sp-001"}
_MODEL_RE = re.compile(r"^claude-[a-z0-9][a-z0-9.-]*$")


def model_looks_valid(model: str) -> bool:
    """The endpoint is Anthropic's Messages API, so a usable id is a Claude model id (claude-…)."""
    return bool(_MODEL_RE.match((model or "").strip()))


def migrate_model_setting(settings) -> bool:
    """Reset a stored placeholder model to the default (empty = DEFAULT_MODEL). Returns True if changed."""
    cur = (settings.value("ai/model", "", type=str) or "").strip()
    if cur in _PLACEHOLDER_MODELS:
        settings.setValue("ai/model", "")
        return True
    return False


class TriageError(RuntimeError):
    """A failed Triage/API call, carrying the HTTP status (0 = never reached the server) for the UI."""

    def __init__(self, status: int, reason: str):
        self.status = status
        self.reason = reason
        super().__init__(f"HTTP {status}: {reason}" if status else reason)


def _api_error(r) -> TriageError:
    """Turn an HTTP error response into a short, specific message: {"type":"error","error":{type,message}}."""
    etype, msg = "", ""
    try:
        err = (r.json() or {}).get("error") or {}
        etype, msg = str(err.get("type", "")), str(err.get("message", ""))
    except ValueError:
        msg = (r.text or "").strip()[:200]
    hint = {400: "the request was rejected", 401: "the API key was rejected — check Settings → AI",
            403: "this key isn't allowed to use that model", 404: "unknown model or endpoint — check Settings → AI → Model",
            413: "the input is too large — trim it", 429: "rate limited — wait and retry",
            529: "the API is overloaded — retry shortly"}.get(r.status_code,
                                                              "server error — retry later" if r.status_code >= 500
                                                              else "request failed")
    detail = f"{hint}" + (f" ({etype}: {msg})" if msg else "")
    return TriageError(r.status_code, detail[:400])


def _post(api_key: str, body: dict, timeout: int):
    try:
        r = requests.post(API_URL, headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                                            "content-type": "application/json"},
                          data=json.dumps(body), timeout=timeout)
    except requests.Timeout:
        raise TriageError(0, f"no response from {API_URL} within {timeout}s (timed out)") from None
    except requests.RequestException as e:
        raise TriageError(0, f"can't reach {API_URL}: {type(e).__name__}") from None
    if r.status_code >= 400:
        raise _api_error(r)
    try:
        return r.json()
    except ValueError:
        raise TriageError(r.status_code, "the endpoint returned a non-JSON response") from None


def test_connection(api_key: str, model: str = DEFAULT_MODEL, timeout: int = 20) -> str:
    """Settings → AI → Test connection: a minimal request proving key + model + network work."""
    if not api_key:
        raise TriageError(0, "No API key set.")
    model = (model or DEFAULT_MODEL).strip()
    if not model_looks_valid(model):
        raise TriageError(0, f"'{model}' is not a Claude model id (expected e.g. {DEFAULT_MODEL}).")
    data = _post(api_key, {"model": model, "max_tokens": 16,
                           "messages": [{"role": "user", "content": "Reply with the word OK."}]}, timeout)
    return f"Connected — {data.get('model', model)} responded."

SYSTEM_PROMPT = """You are an Application Security Triage Assistant supporting an authorized penetration tester. \
Your role is to analyze HTTP request/response pairs, API schemas, or source code to identify potential security \
weaknesses (such as XSS, SSRF, and SQLi) and assist with defensive remediation.

STRICT OPERATIONAL RULES:
1. SCOPE ENFORCEMENT: Only analyze targets explicitly listed in the provided AUTHORIZED_SCOPE. Refuse any request \
targeting out-of-scope domains or IPs.
2. HUMAN-IN-THE-LOOP (HITL): Never execute network requests autonomously. You may only analyze provided logs/code \
and propose non-destructive verification steps for the human operator to review and execute manually.
3. NON-DESTRUCTIVE VERIFICATION ONLY: When suggesting test inputs to verify a finding, use only benign, \
non-destructive canary strings (e.g., unique alphanumeric markers for reflection, safe boolean/timing checks \
without data extraction, or authorized internal canary endpoints). Never generate weaponized payloads, data \
exfiltration queries, or state-modifying exploits.
4. OUTPUT FORMAT: For each potential issue found, provide:
   - Vulnerability Class & CWE ID
   - Affected Endpoint & Parameter
   - Root Cause Analysis (why the input handling appears unsafe)
   - Safe Manual Verification Step (for the human tester to run)
   - Remediation & Secure Code Fix

AUTHORIZED_SCOPE: {scope}"""


def triage(content: str, scope: str, api_key: str, model: str = DEFAULT_MODEL, timeout: int = 90) -> str:
    """Analyze content and return the assistant's structured triage text. Raises TriageError on failure."""
    if not api_key:
        raise TriageError(0, "No API key set. Add one in Settings → AI.")
    if not content.strip():
        raise TriageError(0, "Nothing to analyze — paste a request/response, API schema, or code.")
    model = (model or DEFAULT_MODEL).strip()
    if not model_looks_valid(model):
        raise TriageError(0, f"'{model}' is not a Claude model id. Fix it in Settings → AI → Model "
                             f"(or clear it to use {DEFAULT_MODEL}).")
    system = SYSTEM_PROMPT.replace("{scope}", scope or "(no scope set — treat everything as OUT OF SCOPE and refuse)")
    data = _post(api_key, {"model": model, "max_tokens": 4096, "system": system,
                           "messages": [{"role": "user", "content": content}]}, timeout)
    parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
    text = "\n".join(parts).strip()
    if data.get("stop_reason") == "refusal":
        why = ((data.get("stop_details") or {}).get("explanation") or "").strip()
        return (text + "\n\n" if text else "") + "[The model declined this request" + (f": {why}" if why else "") + "]"
    if not text:
        raise TriageError(200, f"the model returned no text (stop_reason: {data.get('stop_reason', 'unknown')})")
    if data.get("stop_reason") == "max_tokens":
        text += "\n\n[output truncated at the token limit]"
    return text
