#------------------------------------------------------------------------------
# Wyrm — wyrm/security/audit/advice.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Remediation guidance and references per check, so scanner findings export as an actionable report."""
from __future__ import annotations

ADVICE = {
    "xss": ("Contextually output-encode all user-supplied data (HTML, attribute, JS, URL contexts); prefer a "
            "template engine with automatic escaping and add a strong Content-Security-Policy.",
            ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
             "https://owasp.org/www-community/attacks/xss/"]),
    "sqli": ("Use parameterised queries / prepared statements — never build SQL by string concatenation — and run "
             "the database with a least-privilege account.",
             ["https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"]),
    "ssti": ("Never pass user input into template source; use a logic-less/sandboxed template engine and pass user "
             "data only as context variables.",
             ["https://portswigger.net/web-security/server-side-template-injection"]),
    "traversal": ("Resolve requested paths against a fixed base directory and reject traversal sequences; prefer an "
                  "allow-list of permitted filenames rather than taking a path from the user.",
                  ["https://owasp.org/www-community/attacks/Path_Traversal"]),
    "open-redirect": ("Do not redirect to user-supplied URLs. Use an allow-list of destinations, or only relative "
                      "paths, and reject absolute/scheme-relative targets.",
                      ["https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"]),
    "crlf": ("Strip CR/LF characters from any value written into a response header; use the framework's header API "
             "(which rejects control characters) rather than building headers by hand.",
             ["https://owasp.org/www-community/attacks/HTTP_Response_Splitting"]),
    "ssrf": ("Allow-list the outbound hosts the server may reach, block internal/link-local ranges (including cloud "
             "metadata 169.254.169.254), and re-validate after DNS resolution.",
             ["https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"]),
    "cmdi": ("Avoid invoking a shell. Call programs with an argument array (no shell string), and strictly "
             "validate/allow-list any user input that reaches a command.",
             ["https://owasp.org/www-community/attacks/Command_Injection"]),
    "passive": ("Harden the response: set the missing security headers, mark cookies Secure/HttpOnly, and avoid "
                "returning verbose errors or stack traces to clients.",
                ["https://owasp.org/www-project-secure-headers/"]),
}


def advice(check_key: str):
    """(remediation_text, [reference_urls]) for a check key; empty strings/list if unknown."""
    return ADVICE.get(check_key, ("", []))
