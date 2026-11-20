// Injected into every page (isolated world). Inspired by CiteSee (Chang et al., CHI 2023):
// finds links to papers (arXiv / DOI), highlights the ones in the reader's history,
// and returns the list of papers this page links to.
(function (known) {
  const AX = /arxiv\.org\/(?:abs|pdf|html)\/((?:\d{4}\.\d{4,5})|(?:[a-z\-]+(?:\.[A-Z]{2})?\/\d{7}))/i;
  const DOI = /(10\.\d{4,9}\/[^\s"'<>?#&]+)/i;

  function keyOf(href) {
    let h = href;
    try { h = decodeURIComponent(href); } catch (e) {}
    let m = h.match(AX);
    if (m) return "arxiv:" + m[1];
    m = h.match(DOI);
    if (m) {
      let d = m[1].toLowerCase().replace(/[.,;)\/]+$/, "").replace(/\/(full|pdf|abstract|epdf|meta)$/, "");
      if (d.startsWith("10.48550/arxiv.")) return "arxiv:" + d.slice(15);
      return "doi:" + d;
    }
    return null;
  }

  const root = document.head || document.documentElement;
  if (root && !document.getElementById("__scholar_style")) {
    const s = document.createElement("style");
    s.id = "__scholar_style";
    s.textContent =
      "a[data-scholar=read]{background:rgba(255,170,0,.20)!important;border-radius:3px}" +
      "a[data-scholar=saved]{background:rgba(0,170,90,.22)!important;border-radius:3px}" +
      ".__scholar_badge{font:600 10px/1.4 system-ui,sans-serif!important;margin-left:4px;padding:0 5px;" +
      "border-radius:8px;color:#fff!important;vertical-align:middle;white-space:nowrap}";
    root.appendChild(s);
  }

  const here = location.href;
  const found = {};
  document.querySelectorAll("a[href]").forEach((a) => {
    const k = keyOf(a.href);
    if (!k) return;
    const text = (a.innerText || a.title || "").trim().replace(/\s+/g, " ").slice(0, 200);
    if (!found[k] || text.length > found[k].text.length) found[k] = { key: k, href: a.href, text: text };

    const st = known[k];
    if (st && a.dataset.scholar !== st && keyOf(here) !== k) {
      a.dataset.scholar = st;
      a.querySelectorAll(".__scholar_badge").forEach((b) => b.remove());
      const b = document.createElement("span");
      b.className = "__scholar_badge";
      b.style.background = st === "saved" ? "#0a7d4f" : "#c77700";
      b.textContent = st === "saved" ? "★ saved" : "✓ read";
      a.appendChild(b);
    }
  });
  return JSON.stringify(Object.values(found)); // JSON survives the JS->Python bridge reliably
})(__KNOWN__);
