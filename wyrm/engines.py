#------------------------------------------------------------------------------
# Wyrm — wyrm/engines.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Search-engine integration: bangs, default engine, and smart address-bar parsing."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import quote, quote_plus


@dataclass(frozen=True)
class Engine:
    key: str
    name: str
    template: str  # "{q}" is replaced by the url-encoded query
    home: str

    def url(self, query: str) -> str:
        return self.template.replace("{q}", quote_plus(query))


# "research" is our own federated scholarly search (arXiv + Semantic Scholar), served on wyrm://
RESEARCH = Engine("r", "Papers (arXiv + Semantic Scholar)", "wyrm://search?q={q}", "wyrm://home")

SECURITY = Engine("sec", "Security Search", "wyrm://sec?q={q}", "wyrm://home")

ENGINES: dict[str, Engine] = {
    e.key: e
    for e in [
        SECURITY,
        RESEARCH,
        Engine("ddg", "DuckDuckGo", "https://duckduckgo.com/?q={q}", "https://duckduckgo.com"),
        Engine("g", "Google", "https://www.google.com/search?q={q}", "https://www.google.com"),
        Engine("b", "Bing", "https://www.bing.com/search?q={q}", "https://www.bing.com"),
        Engine("brave", "Brave Search", "https://search.brave.com/search?q={q}", "https://search.brave.com"),
        Engine("gs", "Google Scholar", "https://scholar.google.com/scholar?q={q}", "https://scholar.google.com"),
        Engine("arxiv", "arXiv", "https://arxiv.org/search/?query={q}&searchtype=all", "https://arxiv.org"),
        Engine("s2", "Semantic Scholar", "https://www.semanticscholar.org/search?q={q}", "https://www.semanticscholar.org"),
        Engine("pm", "PubMed", "https://pubmed.ncbi.nlm.nih.gov/?term={q}", "https://pubmed.ncbi.nlm.nih.gov"),
        Engine("wiki", "Wikipedia", "https://en.wikipedia.org/w/index.php?search={q}", "https://en.wikipedia.org"),
        Engine("gh", "GitHub", "https://github.com/search?q={q}&type=repositories", "https://github.com"),
        # security sources
        Engine("cve", "NVD (CVEs)", "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query={q}",
               "https://nvd.nist.gov/vuln/search"),
        Engine("edb", "Exploit-DB", "https://www.exploit-db.com/search?q={q}", "https://www.exploit-db.com"),
        Engine("crt", "crt.sh (certificates)", "https://crt.sh/?q={q}", "https://crt.sh"),
        Engine("shodan", "Shodan", "https://www.shodan.io/search?query={q}", "https://www.shodan.io"),
        Engine("h1", "HackerOne Hacktivity", "https://hackerone.com/hacktivity/overview?queryString={q}",
               "https://hackerone.com/hacktivity"),
        Engine("wb", "Wayback Machine", "https://web.archive.org/web/*/{q}*", "https://web.archive.org"),
    ]
}

DEFAULT_ENGINE = "sec"

_KNOWN_SCHEMES = ("http", "https", "file", "wyrm", "about", "chrome", "view-source", "data")
_ARXIV_ID = re.compile(r"^(?:arxiv:\s*)?(\d{4}\.\d{4,5}(?:v\d+)?|[a-z\-]+(?:\.[A-Z]{2})?/\d{7})$", re.I)
_DOI = re.compile(r"^(?:doi:\s*)?(10\.\d{4,9}/\S+)$", re.I)
_BANG = re.compile(r"^!(\w+)(?:\s+(.*))?$|^(.*?)\s+!(\w+)$", re.S)
_HOSTLIKE = re.compile(r"^(localhost|\d{1,3}(\.\d{1,3}){3}|[\w-]+(\.[\w-]+)*\.[a-z]{2,})(:\d+)?([/?#].*)?$", re.I)


def research_url(query: str) -> str:
    return RESEARCH.url(query)


def resolve(text: str, default_engine: str = DEFAULT_ENGINE) -> str:
    """Turn whatever the user typed in the address bar into a URL.

    Supports: full URLs, bare hostnames, arXiv ids ("2308.07915", "arXiv:2308.07915"),
    DOIs ("10.1038/nature23879"), bangs ("!gs surface code" or "surface code !gs"),
    and plain queries routed to the default engine.
    """
    t = text.strip()
    if not t:
        return RESEARCH.home

    m = _BANG.match(t)
    if m:
        bang = (m.group(1) or m.group(4) or "").lower()
        query = (m.group(2) if m.group(1) else m.group(3)) or ""
        if bang in ENGINES:
            eng = ENGINES[bang]
            return eng.url(query.strip()) if query.strip() else eng.home

    if m := re.match(r"^(CVE-\d{4}-\d{4,}|CWE-\d+|T\d{4}(?:\.\d{3})?)$", t, re.I):
        return SECURITY.url(m.group(1).upper())  # security identifiers always go to Security Search
    if m := _ARXIV_ID.match(t):
        return f"https://arxiv.org/abs/{m.group(1)}"
    if m := _DOI.match(t):
        return f"https://doi.org/{m.group(1)}"

    scheme = t.split(":", 1)[0].lower() if ":" in t else ""
    if scheme in _KNOWN_SCHEMES:
        return t
    # a local file path typed without the file:// scheme — open it instead of searching for it:
    #   Windows drive path (C:\… or C:/…), or a UNC path (\\server\share). Percent-encode the path so spaces
    #   and other special characters (common in Windows paths) survive as a valid URL.
    if re.match(r"^[A-Za-z]:[\\/]", t):
        return "file:///" + quote(t.replace("\\", "/"), safe="/:")
    if t.startswith("\\\\"):
        return "file:" + quote(t.replace("\\", "/"), safe="/:")
    if " " not in t and _HOSTLIKE.match(t):
        host = t.split("/", 1)[0]
        local = host.startswith("localhost") or re.match(r"^\d", host)
        return ("http://" if local else "https://") + t

    eng = ENGINES.get(default_engine, ENGINES[DEFAULT_ENGINE])
    return eng.url(t)
