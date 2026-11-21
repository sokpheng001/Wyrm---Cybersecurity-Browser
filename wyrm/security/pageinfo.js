/*
 * Wyrm — wyrm/security/pageinfo.js
 * Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
 * Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
 * Authors: @oda, @sopi, @kwan
 */
// Read-only snapshot of the current page for passive analysis. Runs in the page's main world
// (needed to see library globals like jQuery.fn.jquery). Never modifies the page.
(function () {
  const r = { url: location.href, https: location.protocol === "https:" };
  const scripts = Array.from(document.scripts);
  r.scripts = scripts.map((s) => s.src).filter(Boolean).slice(0, 200);
  r.inline = scripts.filter((s) => !s.src).map((s) => s.textContent.slice(0, 150000)).slice(0, 40);
  const meta = document.querySelector("meta[name=generator]");
  r.generator = meta ? meta.content : "";

  r.forms = Array.from(document.forms).slice(0, 50).map((f) => ({
    action: f.action, method: (f.getAttribute("method") || "get").toLowerCase(),
    password: !!f.querySelector("input[type=password]"),
    csrf: !!f.querySelector("input[type=hidden][name*=csrf i],input[type=hidden][name*=token i],input[type=hidden][name*=xsrf i]"),
  }));

  r.mixed = [];
  if (r.https) {
    document.querySelectorAll("script[src],iframe[src],img[src],link[rel=stylesheet][href],audio[src],video[src],source[src],embed[src],object[data]")
      .forEach((el) => {
        const u = el.src || el.href || el.data || "";
        if (u.startsWith("http:")) r.mixed.push({ tag: el.tagName.toLowerCase(), url: u });
      });
  }

  r.comments = [];
  const tw = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
  while (tw.nextNode() && r.comments.length < 80) {
    const t = tw.currentNode.nodeValue.trim();
    if (t.length > 3) r.comments.push(t.slice(0, 300));
  }

  const g = {};
  try { if (window.jQuery && jQuery.fn) g.jquery = jQuery.fn.jquery; } catch (e) {}
  try { if (window.React && React.version) g.react = React.version; } catch (e) {}
  try { if (window.angular && angular.version) g.angularjs = angular.version.full; } catch (e) {}
  try { const ng = document.querySelector("[ng-version]"); if (ng) g.angular = ng.getAttribute("ng-version"); } catch (e) {}
  try { if (window.Vue && Vue.version) g.vue = Vue.version; } catch (e) {}
  try { if (window._ && _.VERSION) g.lodash = _.VERSION; } catch (e) {}
  try { if (window.moment && moment.version) g.moment = moment.version; } catch (e) {}
  try { if (window.bootstrap && bootstrap.Tooltip) g.bootstrap = bootstrap.Tooltip.VERSION; } catch (e) {}
  try { if (window.jQuery && jQuery.fn && jQuery.fn.tooltip && jQuery.fn.tooltip.Constructor) g.bootstrap = g.bootstrap || jQuery.fn.tooltip.Constructor.VERSION; } catch (e) {}
  try { if (window.DOMPurify && DOMPurify.version) g.dompurify = DOMPurify.version; } catch (e) {}
  try { if (window.Handlebars && Handlebars.VERSION) g.handlebars = Handlebars.VERSION; } catch (e) {}
  if (window.__NEXT_DATA__) g["next.js"] = "";
  if (window.__NUXT__) g["nuxt"] = "";
  if (document.querySelector("[href*='wp-content'],[src*='wp-content']")) g.wordpress = "";
  if (window.Drupal) g.drupal = "";
  if (window.Shopify) g.shopify = "";
  r.globals = g;

  try { r.jsCookies = document.cookie ? document.cookie.split(";").map((c) => c.split("=")[0].trim()) : []; } catch (e) { r.jsCookies = []; }
  try { r.localStorage = Object.keys(localStorage).slice(0, 100); } catch (e) { r.localStorage = []; }
  try { r.sessionStorage = Object.keys(sessionStorage).slice(0, 100); } catch (e) { r.sessionStorage = []; }
  r.iframes = document.querySelectorAll("iframe").length;
  r.postMessage = !!(window.onmessage);
  return JSON.stringify(r);
})();
