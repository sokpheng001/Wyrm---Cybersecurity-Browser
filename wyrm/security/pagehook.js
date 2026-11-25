/*
 * Wyrm — wyrm/security/pagehook.js
 * Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
 * Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
 * Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
 */
/* B2: document-start hook for passive page info. Counts "message" (postMessage) listeners registered on window —
   addEventListener("message", …) is the common case and was invisible to pageinfo.js, which only saw
   window.onmessage. Leaves no page-readable global: pageinfo.js reads the count by calling
   addEventListener("__WYRM_HOOK_TOKEN__", cb) with a per-session secret event type, which this wrapper answers
   instead of registering — passing the count plus the native JSON.stringify/Object.keys/Array.isArray saved
   here, so the snapshot can't be rewritten by a page that replaced them later. The wrapper keeps the native name/length/toString so pages can't easily spot it.
   Read-only: every real call is passed straight through to the native method. */
(function () {
  "use strict";
  var TOK = "__WYRM_HOOK_TOKEN__";
  var _apply = Reflect.apply, _dp = Object.defineProperty, _gopd = Object.getOwnPropertyDescriptor;
  var _WM = WeakMap, _get = WeakMap.prototype.get, _set = WeakMap.prototype.set,
      _has = WeakMap.prototype.has, _del = WeakMap.prototype.delete;
  var ET = EventTarget.prototype, _ael = ET.addEventListener, _rel = ET.removeEventListener;
  var _prevToString = Function.prototype.toString;
  var listeners = new _WM(), count = 0, originals = new _WM();
  // built-ins pageinfo.js needs to serialize its snapshot, saved before any page script can replace them
  var tools = Object.freeze(Object.assign(Object.create(null), {
    stringify: JSON.stringify, keys: Object.keys, isArray: Array.isArray }));

  function isWin(t) { return t == null || t === window; }   // unqualified addEventListener(): this is undefined
  function disguise(fake, real) {
    try { _dp(fake, "name", { value: real.name, configurable: true }); } catch (e) {}
    try { _dp(fake, "length", { value: real.length, configurable: true }); } catch (e) {}
    _apply(_set, originals, [fake, real]);
    return fake;
  }
  function replace(obj, name, fake, real) {
    var d = _gopd(obj, name);
    _dp(obj, name, { value: disguise(fake, real), writable: d.writable, enumerable: d.enumerable,
                     configurable: d.configurable });
  }
  var ael = ({ addEventListener(type, listener) {
    if (type === TOK && typeof listener === "function") {
      try { listener(count, tools); } catch (e) {}
      return undefined;
    }
    try {
      if (type === "message" && isWin(this) && listener && !_apply(_has, listeners, [listener])) {
        _apply(_set, listeners, [listener, 1]);
        count++;
      }
    } catch (e) {}
    return _apply(_ael, this, arguments);
  } }).addEventListener;
  var rel = ({ removeEventListener(type, listener) {
    try {
      if (type === "message" && isWin(this) && listener && _apply(_has, listeners, [listener])) {
        _apply(_del, listeners, [listener]);
        count--;
      }
    } catch (e) {}
    return _apply(_rel, this, arguments);
  } }).removeEventListener;
  // Chains with any earlier toString mask (e.g. anti-fingerprinting): unknown functions go to the previous one.
  var ts = ({ toString() {
    var o = _apply(_get, originals, [this]);
    return _apply(_prevToString, o !== undefined ? o : this, arguments);
  } }).toString;
  try {
    replace(ET, "addEventListener", ael, _ael);
    replace(ET, "removeEventListener", rel, _rel);
    replace(Function.prototype, "toString", ts, _prevToString);
  } catch (e) {}
})();
