#------------------------------------------------------------------------------
# Wyrm — wyrm/security/triage.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: @oda, @sopi, @kwan
#------------------------------------------------------------------------------
"""AI Triage: a scope-gated, human-in-the-loop, non-destructive AppSec analysis assistant.

It sends a request/response pair, API schema, or source code to an LLM (the user's own API key) and
returns structured findings + SAFE manual verification steps + remediation. It never sends network
requests itself and only ever proposes benign canary checks — the operating rules are baked into the
system prompt below.
"""
from __future__ import annotations

import json

import requests

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "kim-modeling-sp-001"

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
    """Analyze content and return the assistant's structured triage text. Raises on API/HTTP error."""
    if not api_key:
        raise RuntimeError("No API key set. Add one in Settings → AI.")
    if not content.strip():
        raise RuntimeError("Nothing to analyze — paste a request/response, API schema, or code.")
    system = SYSTEM_PROMPT.replace("{scope}", scope or "(no scope set — treat everything as OUT OF SCOPE and refuse)")
    r = requests.post(
        API_URL,
        headers={"x-api-key": api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        data=json.dumps({"model": model, "max_tokens": 2048, "system": system,
                         "messages": [{"role": "user", "content": content}]}),
        timeout=timeout,
    )
    if r.status_code == 401:
        raise RuntimeError("API key rejected (401). Check Settings → AI.")
    if r.status_code == 429:
        raise RuntimeError("Rate limited (429). Wait and retry.")
    r.raise_for_status()
    data = r.json()
    parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
    return "\n".join(parts).strip() or "(empty response)"
