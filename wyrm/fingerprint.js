/*
 * Wyrm — wyrm/fingerprint.js
 * Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
 * Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
 * Authors: @oda, @sopi, @kwan
 */
// Anti-fingerprinting (main world, document start). Based on PriVaricator (Nikiforakis et al., WWW 2015):
// add tiny per-session "white lies" to high-entropy fingerprinting surfaces so a fingerprint can't be
// linked across sessions, while keeping breakage minimal. Noise is seeded per page-session (stable within
// a page, different next time), and only perturbs READBACK paths fingerprinters use.
(function () {
  if (window.__wyrmFP) return;
  window.__wyrmFP = true;
  var seed = (Math.random() * 2147483647) | 0;
  function rnd() { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed / 0x7fffffff; }

  // --- canvas: perturb a handful of pixels on readback (invisible, defeats canvas hashing) ---
  function noisify(canvas) {
    try {
      var ctx = canvas.getContext("2d");
      if (!ctx || !canvas.width || !canvas.height) return;
      var n = Math.min(16, Math.max(1, (canvas.width * canvas.height) / 50000 | 0));
      for (var i = 0; i < n; i++) {
        var x = (rnd() * canvas.width) | 0, y = (rnd() * canvas.height) | 0;
        var d = ctx.getImageData(x, y, 1, 1);
        d.data[0] ^= 1; d.data[1] ^= 1; d.data[2] ^= 1;   // flip low bit of RGB…
        d.data[3] = d.data[3] > 0 ? d.data[3] - 1 : 1;     // …and nudge alpha so transparent pixels change too
        ctx.putImageData(d, x, y);
      }
    } catch (e) {}
  }
  var toDataURL = HTMLCanvasElement.prototype.toDataURL;
  HTMLCanvasElement.prototype.toDataURL = function () { noisify(this); return toDataURL.apply(this, arguments); };
  var toBlob = HTMLCanvasElement.prototype.toBlob;
  if (toBlob) HTMLCanvasElement.prototype.toBlob = function () { noisify(this); return toBlob.apply(this, arguments); };
  var getImageData = CanvasRenderingContext2D.prototype.getImageData;
  CanvasRenderingContext2D.prototype.getImageData = function (sx, sy, sw, sh) {
    var d = getImageData.apply(this, arguments);
    if (sw * sh > 32) { for (var k = 0; k < 8; k++) { var p = (Math.abs(rnd() * d.data.length) | 0) & ~3; d.data[p] ^= 1; } }
    return d;
  };

  // --- audio: tiny noise on AnalyserNode float data (defeats AudioContext fingerprinting) ---
  try {
    var gFD = AnalyserNode.prototype.getFloatFrequencyData;
    AnalyserNode.prototype.getFloatFrequencyData = function (a) {
      gFD.apply(this, arguments);
      for (var i = 0; i < a.length; i += 97) a[i] += (rnd() - 0.5) * 1e-4;
    };
  } catch (e) {}

  // --- normalize high-entropy, low-utility attributes (reduce fingerprint surface) ---
  function def(obj, prop, val) {
    try { Object.defineProperty(obj, prop, { get: function () { return val; }, configurable: true }); } catch (e) {}
  }
  def(navigator, "hardwareConcurrency", 8);        // common value instead of the real core count
  def(navigator, "deviceMemory", 8);
  def(navigator, "maxTouchPoints", 0);
  try { if (navigator.plugins && navigator.plugins.length) def(navigator, "plugins", Object.freeze([])); } catch (e) {}

  // --- WebGL: report a generic vendor/renderer (a strong fingerprinting signal) ---
  try {
    var params = { 37445: "Google Inc.", 37446: "ANGLE (Generic Renderer)" };  // UNMASKED_VENDOR/RENDERER
    [window.WebGLRenderingContext, window.WebGL2RenderingContext].forEach(function (G) {
      if (!G) return;
      var gp = G.prototype.getParameter;
      G.prototype.getParameter = function (p) { return params[p] !== undefined ? params[p] : gp.apply(this, arguments); };
    });
  } catch (e) {}
})();
