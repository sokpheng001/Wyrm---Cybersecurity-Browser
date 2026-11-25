/*
 * Wyrm — wyrm/capture.js
 * Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
 * Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
 * Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
 */
/* In-page API & WebSocket capture. Injected (opt-in) so the Security panel can show fetch/XHR
   request+response bodies and WebSocket frames without a MITM proxy. Reports via a sentinel console message
   that Wyrm's page object intercepts. Read-only; bodies are capped.

   F1 (v0.5.0 build hardening): this script runs at document creation, before any page script. Every built-in
   it uses later is captured NOW and only ever called through the saved copy (Reflect.apply), so a page that
   later replaces JSON.stringify / Date.now / Promise.prototype.then / getters etc. cannot choose what we emit.
   Records are null-prototype objects so a page-defined Object.prototype.toJSON or setter can't rewrite them.
   The Python side still validates every record strictly and labels these rows "page-reported": a hook that
   lives in the page's own JS world can never be fully trusted — the intercepting proxy is the trusted source. */
(function () {
  "use strict";
  // ---- saved built-ins (must stay at the very top) ------------------------------------------------------
  var _apply = Reflect.apply;
  var _cd = (window.console && console.debug) ? console.debug : function () {};
  var _con = window.console;
  var _stringify = JSON.stringify;
  var _now = Date.now;
  var _String = String;
  var _create = Object.create;
  var _keys = Object.keys;
  var _gopd = Object.getOwnPropertyDescriptor;
  var _isArray = Array.isArray;
  var _URL = window.URL;
  var _urlHref = null;   // assigned below once getter() exists
  var _then = Promise.prototype.then;
  var _ael = EventTarget.prototype.addEventListener;
  var _slice = String.prototype.slice;
  var _upper = String.prototype.toUpperCase;
  var _WM = WeakMap, _wmGet = WeakMap.prototype.get, _wmSet = WeakMap.prototype.set;
  function getter(proto, name) {
    try { var d = _gopd(proto, name); return d && d.get; } catch (e) { return undefined; }
  }
  var _Request = window.Request, _Headers = window.Headers, _ArrayBuffer = window.ArrayBuffer, _Blob = window.Blob;
  var _reqClone = _Request && _Request.prototype.clone, _reqText = _Request && _Request.prototype.text;
  var _reqUrl = _Request && getter(_Request.prototype, "url");
  var _reqMethod = _Request && getter(_Request.prototype, "method");
  var _reqHeaders = _Request && getter(_Request.prototype, "headers");
  var _reqBody = _Request && getter(_Request.prototype, "body");
  var _resClone = window.Response && Response.prototype.clone;
  var _resText = window.Response && Response.prototype.text;
  var _resStatus = window.Response && getter(Response.prototype, "status");
  var _hForEach = _Headers && _Headers.prototype.forEach;
  var _abLen = _ArrayBuffer && getter(_ArrayBuffer.prototype, "byteLength");
  var _blobSize = _Blob && getter(_Blob.prototype, "size");
  var _msgData = window.MessageEvent && getter(MessageEvent.prototype, "data");
  var _href = getter(Location.prototype, "href") || null;
  _urlHref = getter(_URL.prototype, "href");

  var P = "[[WYRMCAP:__WYRM_CAP_TOKEN__]]";   // __WYRM_CAP_TOKEN__ is replaced with a random secret at injection
  var MAX = 12000;

  function call(fn, self, args) { return _apply(fn, self, args || []); }
  function str(v) { try { return _String(v); } catch (e) { return ""; } }
  function isA(v, C) { try { return !!C && v instanceof C; } catch (e) { return false; } }
  function rec() { return _create(null); }
  function here() { try { return _href ? call(_href, location) : str(location.href); } catch (e) { return ""; } }
  function absolute(u) {
    try { return call(_urlHref, new _URL(str(u), here())); } catch (e) { return str(u); }
  }
  function clip(s) {
    if (s == null) return "";
    if (typeof s !== "string") {
      if (isA(s, _ArrayBuffer)) return "[binary " + call(_abLen, s) + " bytes]";
      if (isA(s, _Blob)) return "[blob " + call(_blobSize, s) + " bytes]";
      try { var j = call(_stringify, JSON, [s]); s = (j === undefined) ? str(s) : j; } catch (e) { s = str(s); }
    }
    return s.length > MAX ? call(_slice, s, [0, MAX]) + "…[truncated]" : s;
  }
  function emit(o) {
    try { o.t = call(_now, Date); call(_cd, _con, [P + call(_stringify, JSON, [o])]); } catch (e) {}
  }
  function method(m) { return call(_upper, str(m || "GET")); }
  function headersOf(h) {   // Headers | [[k,v],…] | {k:v} -> null-prototype {k: v}
    var out = rec(), n = 0;
    try {
      if (!h) return out;
      if (isA(h, _Headers)) {
        call(_hForEach, h, [function (v, k) { if (n++ < 64) out[str(k)] = clip(str(v)); }]);
      } else if (_isArray(h)) {
        for (var i = 0; i < h.length && i < 64; i++) out[str(h[i][0])] = clip(str(h[i][1]));
      } else if (typeof h === "object") {
        var ks = _keys(h);
        for (var j = 0; j < ks.length && j < 64; j++) out[str(ks[j])] = clip(str(h[ks[j]]));
      }
    } catch (e) {}
    return out;
  }

  // ---- fetch ----------------------------------------------------------------------------------------------
  var of = window.fetch;
  if (of) {
    window.fetch = function fetch(input, init) {
      var r = null, reqBody = null;
      try {   // read everything BEFORE the native call: fetch() consumes a Request's body
        var isReq = isA(input, _Request);
        r = rec();
        r.k = "fetch";
        r.url = absolute(isReq ? call(_reqUrl, input) : input);
        r.method = method((init && init.method) || (isReq ? call(_reqMethod, input) : "GET"));
        r.headers = headersOf((init && init.headers) || (isReq ? call(_reqHeaders, input) : null));
        r.req = (init && init.body != null) ? clip(init.body) : "";
        if (isReq && !(init && init.body != null) && call(_reqBody, input)) {
          try { reqBody = call(_reqText, call(_reqClone, input)); } catch (e) { reqBody = null; }
        }
      } catch (e) { r = null; }
      var p = call(of, this, arguments);   // the page gets the native promise, untouched
      if (!r) return p;
      try {
        var finish = function (resp) {
          r.status = resp ? call(_resStatus, resp) : 0;
          var t;
          try { t = call(_resText, call(_resClone, resp)); } catch (e) { emit(r); return; }
          call(_then, t, [function (txt) { r.res = clip(txt); emit(r); }, function () { r.res = ""; emit(r); }]);
        };
        var onResp = function (resp) {
          if (reqBody) {
            call(_then, reqBody, [function (b) { r.req = clip(b); finish(resp); }, function () { finish(resp); }]);
          } else { finish(resp); }
        };
        var onErr = function (err) {   // network error / CORS / abort: log it instead of dropping it
          r.status = 0;
          r.error = clip(str(err && err.message ? err.message : err));
          r.res = "";
          emit(r);
        };
        call(_then, p, [onResp, onErr]);
      } catch (e) {}
      return p;
    };
  }

  // ---- XMLHttpRequest -------------------------------------------------------------------------------------
  var OX = window.XMLHttpRequest;
  if (OX) {
    var XP = OX.prototype;
    var op = XP.open, se = XP.send, srh = XP.setRequestHeader;
    var xStatus = getter(XP, "status"), xType = getter(XP, "responseType"),
        xText = getter(XP, "responseText"), xResp = getter(XP, "response");
    var state = new _WM();   // per-request info kept out of the page's sight (no expando properties)
    var st = function (x) {
      var s = call(_wmGet, state, [x]);
      if (!s) { s = rec(); s.headers = rec(); call(_wmSet, state, [x, s]); }
      return s;
    };
    XP.open = function open(m, u) {
      try { var s = st(this); s.method = method(m); s.url = absolute(u); s.headers = rec(); } catch (e) {}
      return call(op, this, arguments);
    };
    XP.setRequestHeader = function setRequestHeader(k, v) {
      try { st(this).headers[str(k)] = clip(str(v)); } catch (e) {}
      return call(srh, this, arguments);
    };
    XP.send = function send(body) {
      var x = this;
      try {
        var s = st(x);
        var req = (body != null) ? clip(body) : "";
        var done = function (failed) {
          return function () {
            try {
              var r = rec();
              r.k = "xhr"; r.url = s.url || ""; r.method = s.method || "GET"; r.headers = s.headers;
              r.req = req; r.status = failed ? 0 : call(xStatus, x);
              var rt = call(xType, x);
              if (failed) { r.res = ""; r.error = "network error"; }
              else if (rt === "" || rt === "text") r.res = clip(call(xText, x));
              else if (rt === "json") r.res = clip(call(xResp, x));
              else if (rt === "document") r.res = "[document]";
              else r.res = clip(call(xResp, x));   // arraybuffer / blob -> "[binary N bytes]"
              emit(r);
            } catch (e) {}
          };
        };
        call(_ael, x, ["load", done(false)]);
        call(_ael, x, ["error", done(true)]);
      } catch (e) {}
      return call(se, this, arguments);
    };
  }

  // ---- WebSocket ------------------------------------------------------------------------------------------
  var OW = window.WebSocket;
  if (OW) {
    var wsSend = OW.prototype.send;
    var wsUrl = new _WM();
    var frame = function (d) { return (typeof d === "string") ? clip(d) : "[binary]"; };
    var wsRec = function (url, ev) { var r = rec(); r.k = "ws"; r.url = url; r.ev = ev; return r; };
    var WS = function WebSocket(url, protocols) {
      var ws = (protocols !== undefined) ? new OW(url, protocols) : new OW(url);
      try {
        var u = absolute(url);
        call(_wmSet, wsUrl, [ws, u]);
        emit(wsRec(u, "open"));
        call(_ael, ws, ["message", function (e) {
          var r = wsRec(u, "recv"); r.res = frame(_msgData ? call(_msgData, e) : e.data); emit(r);
        }]);
        call(_ael, ws, ["close", function () { emit(wsRec(u, "close")); }]);
      } catch (e) {}
      return ws;
    };
    try {
      OW.prototype.send = function send(d) {
        try {
          var u = call(_wmGet, wsUrl, [this]);
          if (u !== undefined) { var r = wsRec(u, "send"); r.req = frame(d); emit(r); }
        } catch (e) {}
        return call(wsSend, this, arguments);
      };
      WS.prototype = OW.prototype;
      WS.CONNECTING = OW.CONNECTING; WS.OPEN = OW.OPEN; WS.CLOSING = OW.CLOSING; WS.CLOSED = OW.CLOSED;
      window.WebSocket = WS;
    } catch (e) {}
  }
})();
