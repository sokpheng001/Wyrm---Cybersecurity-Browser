/*
 * Wyrm — wyrm/youtube.js
 * Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
 * Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
 * Authors: @oda, @sopi, @kwan
 */
// YouTube ad removal (main world, document start). Removes ad slots from player data before the player
// reads them, skips/fast-forwards any ad that still starts, and hides promoted tiles. Counts what it removes.
(function () {
  if (!/(^|\.)youtube\.com$/.test(location.hostname) || window.__hbYoutube) return;
  window.__hbYoutube = true;
  window.__hbYtCount = 0;
  const AD_KEYS = ["adPlacements", "playerAds", "adSlots", "adBreakHeartbeatParams"];
  const strip = (o) => {
    try {
      if (o && typeof o === "object") {
        for (const k of AD_KEYS) if (k in o) { delete o[k]; window.__hbYtCount++; }
        if (o.playerResponse) strip(o.playerResponse);
        if (Array.isArray(o)) o.forEach(strip);
      }
    } catch (e) {}
    return o;
  };
  const parse = JSON.parse;
  JSON.parse = function () { return strip(parse.apply(this, arguments)); };
  let initial;
  try {
    Object.defineProperty(window, "ytInitialPlayerResponse", {
      configurable: true, get() { return initial; }, set(v) { initial = strip(v); },
    });
  } catch (e) {}
  const origFetch = window.fetch;
  window.fetch = async function (...args) {
    const res = await origFetch.apply(this, args);
    try {
      const u = (args[0] && args[0].url) || String(args[0]);
      if (/\/youtubei\/v1\/(player|next|browse)/.test(u)) {
        const data = strip(await res.clone().json());
        return new Response(JSON.stringify(data), { status: res.status, statusText: res.statusText, headers: res.headers });
      }
    } catch (e) {}
    return res;
  };
  // fallback: if an ad still plays, mute it, jump to its end and press skip
  setInterval(() => {
    const p = document.querySelector(".html5-video-player");
    if (p && p.classList.contains("ad-showing")) {
      const v = p.querySelector("video");
      if (v && isFinite(v.duration)) { v.muted = true; v.currentTime = v.duration; }
      document.querySelectorAll(".ytp-ad-skip-button,.ytp-ad-skip-button-modern,.ytp-skip-ad-button").forEach((b) => b.click());
      window.__hbYtCount++;
    }
  }, 300);
  const css = "ytd-ad-slot-renderer,ytd-in-feed-ad-layout-renderer,ytd-promoted-sparkles-web-renderer," +
    "ytd-banner-promo-renderer,#masthead-ad,ytd-player-legacy-desktop-watch-ads-renderer,.ytp-ad-overlay-container," +
    "ytd-rich-item-renderer:has(ytd-ad-slot-renderer),ytd-statement-banner-renderer{display:none!important}";
  const add = () => {
    const s = document.createElement("style");
    s.textContent = css;
    (document.head || document.documentElement).appendChild(s);
  };
  if (document.documentElement) add(); else document.addEventListener("DOMContentLoaded", add);
})();
