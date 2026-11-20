"""Scholarly metadata: detect papers in URLs, fetch metadata, federated search, BibTeX.

Data sources (both free, no key required):
  * Semantic Scholar Graph API  - metadata, TLDR summaries, citation counts
    (set env var S2_API_KEY for higher rate limits)
  * arXiv API                   - metadata + search, used as fallback / second source
"""
from __future__ import annotations

import os
import re
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import unquote

import requests

HEADERS = {"User-Agent": "HiddenBrowser/0.1 (research browser prototype)"}
S2 = "https://api.semanticscholar.org/graph/v1"
S2_FIELDS = "title,authors,year,venue,abstract,tldr,citationCount,referenceCount,externalIds,url,openAccessPdf"
ARXIV_API = "https://export.arxiv.org/api/query"
TIMEOUT = 12

ARXIV_RE = re.compile(
    r"arxiv\.org/(?:abs|pdf|html)/((?:\d{4}\.\d{4,5})|(?:[a-z\-]+(?:\.[A-Z]{2})?/\d{7}))(?:v\d+)?", re.I
)
DOI_RE = re.compile(r"(10\.\d{4,9}/[^\s\"'<>?#&]+)", re.I)


# ---------------------------------------------------------------- paper keys
def normalize_doi(doi: str) -> str:
    d = doi.lower().rstrip(".,;)/")
    d = re.sub(r"/(full|pdf|abstract|epdf|meta)$", "", d)
    return d


def key_from_ids(arxiv: str | None = None, doi: str | None = None, s2id: str | None = None) -> str | None:
    if arxiv:
        return "arxiv:" + re.sub(r"v\d+$", "", arxiv)
    if doi:
        d = normalize_doi(doi)
        if d.startswith("10.48550/arxiv."):
            return "arxiv:" + d[len("10.48550/arxiv."):]
        return "doi:" + d
    if s2id:
        return "s2:" + s2id
    return None


def paper_key_from_url(url: str) -> str | None:
    """Return a stable key like 'arxiv:2308.07915' or 'doi:10.1038/...' for paper URLs."""
    u = unquote(url)
    if m := ARXIV_RE.search(u):
        return key_from_ids(arxiv=m.group(1))
    if m := DOI_RE.search(u):
        return key_from_ids(doi=m.group(1))
    return None


def _s2_id(key: str) -> str:
    kind, ident = key.split(":", 1)
    return {"arxiv": f"arXiv:{ident}", "doi": f"DOI:{ident}", "s2": ident}[kind]


# ---------------------------------------------------------------- Semantic Scholar
def _s2_get(path: str, **params) -> dict:
    headers = dict(HEADERS)
    if key := os.environ.get("S2_API_KEY"):
        headers["x-api-key"] = key
    for attempt in range(2):
        r = requests.get(f"{S2}{path}", params=params, headers=headers, timeout=TIMEOUT)
        if r.status_code != 429 or attempt:
            break
        time.sleep(1.0)  # shared unauthenticated pool is often busy; one quick retry only
    if r.status_code == 429:
        raise RuntimeError("rate-limited (set S2_API_KEY for a dedicated quota)")
    if r.status_code == 404:
        raise RuntimeError("paper not indexed")
    r.raise_for_status()
    return r.json()


def _from_s2(p: dict) -> dict:
    ext = p.get("externalIds") or {}
    arxiv, doi = ext.get("ArXiv"), ext.get("DOI")
    pdf = (p.get("openAccessPdf") or {}).get("url") or (f"https://arxiv.org/pdf/{arxiv}" if arxiv else None)
    return {
        "key": key_from_ids(arxiv, doi, p.get("paperId")),
        "title": p.get("title") or "(untitled)",
        "authors": [a.get("name", "") for a in p.get("authors") or []],
        "year": p.get("year"),
        "venue": p.get("venue") or ("arXiv" if arxiv else ""),
        "abstract": p.get("abstract") or "",
        "tldr": (p.get("tldr") or {}).get("text") or "",
        "citations": p.get("citationCount"),
        "references": p.get("referenceCount"),
        "arxiv": arxiv,
        "doi": doi,
        "url": f"https://arxiv.org/abs/{arxiv}" if arxiv else (f"https://doi.org/{doi}" if doi else p.get("url")),
        "pdf": pdf,
        "source": "Semantic Scholar",
    }


# ---------------------------------------------------------------- arXiv
_ATOM = {"a": "http://www.w3.org/2005/Atom", "arxiv": "http://arxiv.org/schemas/atom"}


def _arxiv_query(**params) -> list[dict]:
    r = requests.get(ARXIV_API, params=params, headers=HEADERS, timeout=TIMEOUT)
    r.raise_for_status()
    root = ET.fromstring(r.content)
    out = []
    for e in root.findall("a:entry", _ATOM):
        id_url = e.findtext("a:id", "", _ATOM)
        m = ARXIV_RE.search(id_url)
        if not m:
            continue
        aid = m.group(1)
        doi = e.findtext("arxiv:doi", None, _ATOM)
        clean = lambda s: re.sub(r"\s+", " ", s or "").strip()  # noqa: E731
        out.append({
            "key": key_from_ids(arxiv=aid),
            "title": clean(e.findtext("a:title", "", _ATOM)),
            "authors": [clean(a.findtext("a:name", "", _ATOM)) for a in e.findall("a:author", _ATOM)],
            "year": int(e.findtext("a:published", "0000", _ATOM)[:4]) or None,
            "venue": clean(e.findtext("arxiv:journal_ref", "", _ATOM)) or "arXiv",
            "abstract": clean(e.findtext("a:summary", "", _ATOM)),
            "tldr": "",
            "citations": None,
            "references": None,
            "arxiv": aid,
            "doi": doi,
            "url": f"https://arxiv.org/abs/{aid}",
            "pdf": f"https://arxiv.org/pdf/{aid}",
            "source": "arXiv",
        })
    return out


# ---------------------------------------------------------------- public API
def fetch_paper(key: str) -> dict:
    """Metadata for one paper. Semantic Scholar first (has TLDR + citations), arXiv as fallback."""
    errors = []
    try:
        return _from_s2(_s2_get(f"/paper/{_s2_id(key)}", fields=S2_FIELDS))
    except Exception as e:  # rate limit, not indexed, offline...
        errors.append(f"Semantic Scholar: {e}")
    if key.startswith("arxiv:"):
        try:
            hits = _arxiv_query(id_list=key.split(":", 1)[1])
            if hits:
                return hits[0]
        except Exception as e:
            errors.append(f"arXiv: {e}")
    raise RuntimeError("; ".join(errors) or "not found")


def _title_norm(t: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (t or "").lower())[:80]


def search(query: str, limit: int = 15) -> dict:
    """Federated search over Semantic Scholar + arXiv, merged and de-duplicated.

    Returns {"results": [...], "errors": [...]}. Results found by both sources are
    merged (S2 metadata wins, sources listed) and ranked first: agreement between
    independent indexes is a cheap relevance signal.
    """
    def s2():
        data = _s2_get("/paper/search", query=query, limit=limit, fields=S2_FIELDS)
        return [_from_s2(p) for p in data.get("data") or []]

    def ax():
        return _arxiv_query(search_query=f"all:{query}", max_results=limit, sortBy="relevance")

    errors, lists = [], []
    with ThreadPoolExecutor(2) as pool:
        futs = {"Semantic Scholar": pool.submit(s2), "arXiv": pool.submit(ax)}
        for name, f in futs.items():
            try:
                lists.append(f.result())
            except Exception as e:
                errors.append(f"{name}: {e}")
                lists.append([])

    merged: dict[str, dict] = {}
    order: list[str] = []
    alias: dict[str, str] = {}  # title-norm / key -> canonical id
    # interleave so both sources contribute to the top of the list
    for i in range(max((len(x) for x in lists), default=0)):
        for lst in lists:
            if i >= len(lst):
                continue
            p = lst[i]
            ids = [p["key"], "t:" + _title_norm(p["title"])]
            canon = next((alias[x] for x in ids if x in alias), None)
            if canon is None:
                canon = p["key"]
                merged[canon] = dict(p, sources=[p["source"]], rank=len(order))
                order.append(canon)
            else:
                m = merged[canon]
                if p["source"] not in m["sources"]:
                    m["sources"].append(p["source"])
                for k, v in p.items():  # fill gaps
                    if not m.get(k) and v:
                        m[k] = v
            for x in ids:
                alias.setdefault(x, canon)

    results = sorted((merged[k] for k in order), key=lambda p: (-len(p["sources"]), p["rank"]))
    return {"results": results, "errors": errors}


def to_bibtex(p: dict) -> str:
    authors = p.get("authors") or []
    last = re.sub(r"\W", "", (authors[0].split()[-1] if authors else "anon").lower())
    first_word = next((w for w in re.findall(r"[A-Za-z]+", p.get("title", "")) if len(w) > 3), "paper")
    citekey = f"{last}{p.get('year') or ''}{first_word.lower()}"
    fields = [
        ("title", "{" + p.get("title", "") + "}"),
        ("author", " and ".join(authors)),
        ("year", str(p.get("year") or "")),
        ("journal", p.get("venue") or ""),
        ("doi", p.get("doi") or ""),
    ]
    if p.get("arxiv"):
        fields += [("eprint", p["arxiv"]), ("archivePrefix", "arXiv")]
    fields.append(("url", p.get("url") or ""))
    entry = "article" if p.get("doi") else "misc"
    body = ",\n".join(f"  {k} = {{{v}}}" for k, v in fields if v)
    return f"@{entry}{{{citekey},\n{body}\n}}"
