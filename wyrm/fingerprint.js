/*
 * Wyrm — wyrm/fingerprint.js
 * Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
 * Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
 * Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
 */
// Anti-fingerprinting (document start). Based on PriVaricator (Nikiforakis et al., WWW 2015): add small
// per-session "white lies" to high-entropy surfaces so a fingerprint can't be linked across sessions, while
// keeping breakage minimal. IMPORTANT (SEC-3): leave NO page-readable global, don't pin tell-tale constants,
// and make canvas/audio noise deterministic within a session so repeated reads of the same input match.
(function () {
  "use strict";
  // One runnable (QWebEngineScript) injected once per document, so no re-entry guard / global flag is needed.
  var SESSION = (Math.random() * 2147483647) | 0;   // per page-session; not exposed anywhere a page can read
  function mkrng(s) { s = (s | 0) || 1; return function () { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; }; }
  function pick(arr, salt) { return arr[(mkrng(SESSION ^ salt)() * arr.length) | 0]; }

  // --- canvas: deterministic perturbation (same canvas + session -> identical output, so two reads match) ---
  function noisify(canvas) {
    try {
      var ctx = canvas.getContext("2d");
      if (!ctx || !canvas.width || !canvas.height) return;
      var rng = mkrng(SESSION ^ (canvas.width * 73856093) ^ (canvas.height * 19349663));
      var n = Math.min(16, Math.max(1, (canvas.width * canvas.height) / 50000 | 0));
      for (var i = 0; i < n; i++) {
        var x = (rng() * canvas.width) | 0, y = (rng() * canvas.height) | 0;
        var d = ctx.getImageData(x, y, 1, 1);
        d.data[0] ^= 1; d.data[1] ^= 1; d.data[2] ^= 1;
        d.data[3] = d.data[3] > 0 ? d.data[3] - 1 : 1;
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
    if (sw * sh > 32) {   // deterministic per region size + session
      var rng = mkrng(SESSION ^ ((sw * 73856093) ^ (sh * 19349663)));
      for (var k = 0; k < 8; k++) { var p = ((rng() * d.data.length) | 0) & ~3; d.data[p] ^= 1; }
    }
    return d;
  };

  // --- audio: deterministic tiny noise on AnalyserNode float data ---
  try {
    var gFD = AnalyserNode.prototype.getFloatFrequencyData;
    AnalyserNode.prototype.getFloatFrequencyData = function (a) {
      gFD.apply(this, arguments);
      var rng = mkrng(SESSION ^ 0x9e3779b1);
      for (var i = 0; i < a.length; i += 97) a[i] += (rng() - 0.5) * 1e-4;
    };
  } catch (e) {}

  // --- realistic, per-session values instead of fixed tells (leave maxTouchPoints / plugins at their real values) ---
  function def(obj, prop, val) {
    try { Object.defineProperty(obj, prop, { get: function () { return val; }, configurable: true }); } catch (e) {}
  }
  def(navigator, "hardwareConcurrency", pick([4, 8, 12, 16], 0x1111));
  def(navigator, "deviceMemory", pick([4, 8], 0x2222));

  // --- WebGL: a realistic, per-session renderer (not a fixed "Generic Renderer" string) ---
  try {
    var renderers = [
      "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)",
      "ANGLE (NVIDIA, NVIDIA GeForce GTX 1660 Direct3D11 vs_5_0 ps_5_0, D3D11)",
      "ANGLE (AMD, AMD Radeon(TM) Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"
    ];
    var params = { 37445: "Google Inc.", 37446: pick(renderers, 0x3333) };   // UNMASKED_VENDOR / RENDERER
    [window.WebGLRenderingContext, window.WebGL2RenderingContext].forEach(function (G) {
      if (!G) return;
      var gp = G.prototype.getParameter;
      G.prototype.getParameter = function (p) { return params[p] !== undefined ? params[p] : gp.apply(this, arguments); };
    });
  } catch (e) {}
})();
