/*
 * Wyrm — wyrm/fingerprint.js
 * Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
 * Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
 * Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
 */
// Anti-fingerprinting (document start). Based on PriVaricator (Nikiforakis et al., WWW 2015): add small
// per-session "white lies" to high-entropy surfaces so a fingerprint can't be linked across sessions, while
// keeping breakage minimal.
//
// F2 (v0.5.0 build hardening) — the lies must not themselves be a fingerprint:
//  (a) the WebGL vendor/renderer pair is chosen by Wyrm (Python) to match the real OS in the user agent;
//  (b) the user's canvas is NEVER written to: exports go through an offscreen copy, and all noise is seeded
//      by session + a hash of the pixels, so the same content always yields the same output;
//  (c) one seed per browser session is substituted in by Python, so every frame/document agrees;
//  (d) spoofed getters live on Navigator.prototype (like the real ones), and every patched function keeps its
//      native name/length and reports "[native code]" from Function.prototype.toString.
// IMPORTANT (SEC-3): leave NO page-readable global.
(function () {
  "use strict";
  // Replaced at injection by wyrm/browser/scripts.py with {"seed":…, "vendor":…, "renderer":…, "cores":[…]}.
  // When the raw file is loaded on its own (e.g. tests/fp/fp.html in a stock browser) we fall back to a random
  // per-document seed and a renderer guessed from the UA.
  var CFG = /*__WYRM_FP_CONFIG__*/null;

  // ---- saved built-ins -----------------------------------------------------------------------------------
  var _apply = Reflect.apply, _defineProperty = Object.defineProperty, _gopd = Object.getOwnPropertyDescriptor;
  var _WM = WeakMap, _wmGet = WeakMap.prototype.get, _wmSet = WeakMap.prototype.set;
  var _fnToString = Function.prototype.toString;
  var _createElement = Document.prototype.createElement;
  var _getContext = HTMLCanvasElement.prototype.getContext;
  var _cw = _gopd(HTMLCanvasElement.prototype, "width").get, _ch = _gopd(HTMLCanvasElement.prototype, "height").get;
  var _setW = _gopd(HTMLCanvasElement.prototype, "width").set, _setH = _gopd(HTMLCanvasElement.prototype, "height").set;
  var _toBlob = HTMLCanvasElement.prototype.toBlob;
  var C2D = CanvasRenderingContext2D.prototype;
  var _getImageData = C2D.getImageData, _putImageData = C2D.putImageData, _drawImage = C2D.drawImage;
  var _idData = _gopd(ImageData.prototype, "data").get;

  if (!CFG) {
    var ua = navigator.userAgent;
    CFG = { seed: (Math.random() * 2147483647) | 0, cores: [4, 8, 12, 16], memory: [4, 8],
            vendor: "Google Inc. (Intel)",
            renderer: /Mac OS X/.test(ua) ? "ANGLE (Apple, ANGLE Metal Renderer: Apple M2, Unspecified Version)"
              : /Windows/.test(ua) ? "ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)"
              : "ANGLE (Intel, Mesa Intel(R) UHD Graphics 620 (KBL GT2), OpenGL 4.6)" };
    if (/Mac OS X/.test(ua)) CFG.vendor = "Google Inc. (Apple)";
  }
  var SESSION = CFG.seed | 0;

  function mkrng(s) {
    s = (s | 0) || 1;
    return function () { s = (s * 1103515245 + 12345) & 0x7fffffff; return s / 0x7fffffff; };
  }
  function pick(arr, salt) { return arr[(mkrng(SESSION ^ salt)() * arr.length) | 0]; }

  // ---- native-looking patches (d) ------------------------------------------------------------------------
  var originals = new _WM();   // patched function -> the native it replaces
  function disguise(fake, real) {
    try { _defineProperty(fake, "name", { value: real.name, configurable: true }); } catch (e) {}
    try { _defineProperty(fake, "length", { value: real.length, configurable: true }); } catch (e) {}
    _apply(_wmSet, originals, [fake, real]);
    return fake;
  }
  function patch(proto, name, makeFake) {   // replaces a data-property method, keeping its attributes
    var d = _gopd(proto, name);
    if (!d || typeof d.value !== "function") return;
    var real = d.value;
    _defineProperty(proto, name, { value: disguise(makeFake(real), real), writable: d.writable,
                                   enumerable: d.enumerable, configurable: d.configurable });
  }
  // Function.prototype.toString: patched functions print their native's source; the wrapper prints its own.
  var tsWrapper = ({
    toString() {
      var o = _apply(_wmGet, originals, [this]);
      return _apply(_fnToString, o !== undefined ? o : this, arguments);
    }
  }).toString;
  (function () {
    var d = _gopd(Function.prototype, "toString");
    _defineProperty(Function.prototype, "toString", { value: disguise(tsWrapper, _fnToString),
      writable: d.writable, enumerable: d.enumerable, configurable: d.configurable });
  })();

  // ---- canvas (b): never touch the user's canvas; deterministic noise from session + content -------------
  function hashPixels(px) {   // FNV-1a over a bounded, evenly spaced sample of the pixel bytes
    var h = 0x811c9dc5 ^ SESSION, n = px.length, step = Math.max(1, (n / 8192) | 0);
    for (var i = 0; i < n; i += step) { h ^= px[i]; h = Math.imul(h, 16777619); }
    h ^= n; return h | 0;
  }
  function perturb(px) {   // flip the low bit of r/g/b on a few pixels chosen by session+content
    var w = 1, h = px.length >> 2;
    if (h <= 32) return;
    var rng = mkrng(hashPixels(px) ^ 0x5bd1e995);
    var count = Math.min(16, Math.max(4, (w * h / 50000) | 0));
    for (var k = 0; k < count; k++) {
      var p = (((rng() * w * h) | 0) * 4);
      px[p] ^= 1; px[p + 1] ^= 1; px[p + 2] ^= 1;
    }
  }
  // Returns a perturbed offscreen copy of `canvas`, or null to fall back to the native call (tainted canvas,
  // zero size, …) — the native call then behaves exactly as it would have, including any SecurityError.
  function noisyCopy(canvas) {
    try {
      var w = _apply(_cw, canvas, []), h = _apply(_ch, canvas, []);
      if (!w || !h) return null;
      var copy = _apply(_createElement, document, ["canvas"]);
      _apply(_setW, copy, [w]); _apply(_setH, copy, [h]);
      var cx = _apply(_getContext, copy, ["2d"]);
      _apply(_drawImage, cx, [canvas, 0, 0]);
      var img = _apply(_getImageData, cx, [0, 0, w, h]);
      perturb(_apply(_idData, img, []));
      _apply(_putImageData, cx, [img, 0, 0]);
      return copy;
    } catch (e) { return null; }
  }
  patch(HTMLCanvasElement.prototype, "toDataURL", function (real) {
    return ({ toDataURL() {
      var c = noisyCopy(this);
      return _apply(real, c || this, arguments);
    } }).toDataURL;
  });
  if (_toBlob) patch(HTMLCanvasElement.prototype, "toBlob", function (real) {
    return ({ toBlob() {
      var c = noisyCopy(this);
      return _apply(real, c || this, arguments);
    } }).toBlob;
  });
  patch(C2D, "getImageData", function (real) {
    return ({ getImageData() {
      var d = _apply(real, this, arguments);   // a fresh copy: perturbing it never touches the canvas
      try { perturb(_apply(_idData, d, [])); } catch (e) {}
      return d;
    } }).getImageData;
  });

  // ---- audio: deterministic tiny noise on AnalyserNode float data ----------------------------------------
  try {
    patch(AnalyserNode.prototype, "getFloatFrequencyData", function (real) {
      return ({ getFloatFrequencyData(a) {
        var r = _apply(real, this, arguments);
        var rng = mkrng(SESSION ^ 0x9e3779b1);
        for (var i = 0; i < a.length; i += 97) a[i] += (rng() - 0.5) * 1e-4;
        return r;
      } }).getFloatFrequencyData;
    });
  } catch (e) {}

  // ---- navigator (c)+(d): one value per browser session, defined where the real getters live -------------
  function spoofGetter(proto, prop, val) {
    try {
      var d = _gopd(proto, prop);
      if (!d || !d.get) return;
      var fake = ({ get [prop]() { return val; } });   // a method-style getter: no .prototype, not newable
      var g = _gopd(fake, prop).get;
      _defineProperty(proto, prop, { get: disguise(g, d.get), set: d.set, enumerable: d.enumerable,
                                     configurable: d.configurable });
    } catch (e) {}
  }
  var NP = Navigator.prototype;
  spoofGetter(NP, "hardwareConcurrency", pick(CFG.cores || [4, 8, 12, 16], 0x1111));
  spoofGetter(NP, "deviceMemory", pick(CFG.memory || [4, 8], 0x2222));
  if (window.WorkerNavigator) spoofGetter(WorkerNavigator.prototype, "hardwareConcurrency",
                                          pick(CFG.cores || [4, 8, 12, 16], 0x1111));

  // ---- WebGL (a): a vendor/renderer pair that matches the real platform ----------------------------------
  try {
    var params = { 37445: CFG.vendor, 37446: CFG.renderer };   // UNMASKED_VENDOR / UNMASKED_RENDERER
    [window.WebGLRenderingContext, window.WebGL2RenderingContext].forEach(function (G) {
      if (!G) return;
      patch(G.prototype, "getParameter", function (real) {
        return ({ getParameter(p) {
          return params[p] !== undefined ? params[p] : _apply(real, this, arguments);
        } }).getParameter;
      });
    });
  } catch (e) {}
})();
