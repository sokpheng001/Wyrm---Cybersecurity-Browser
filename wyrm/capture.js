/* Wyrm — in-page API & WebSocket capture. Injected (opt-in) so the Security panel can show fetch/XHR
   request+response bodies and WebSocket frames without a MITM proxy. Reports via a sentinel console message
   that Wyrm's page object intercepts. Read-only; bodies are capped. */
(function () {
  if (window.__wyrmCap) return;
  window.__wyrmCap = 1;
  var P = "[[WYRMCAP]]";
  var MAX = 12000;
  function clip(s) {
    try { s = (typeof s === "string") ? s : JSON.stringify(s); } catch (e) { s = String(s); }
    if (s == null) return "";
    return s.length > MAX ? s.slice(0, MAX) + "…[truncated]" : s;
  }
  function emit(o) {
    try { o.t = Date.now(); o.page = location.href; console.debug(P + JSON.stringify(o)); } catch (e) {}
  }
  var of = window.fetch;
  if (of) {
    window.fetch = function (input, init) {
      var url = (typeof input === "string") ? input : (input && input.url) || "";
      var method = (init && init.method) || (input && input.method) || "GET";
      var req = (init && init.body) ? clip(init.body) : "";
      return of.apply(this, arguments).then(function (resp) {
        try {
          resp.clone().text().then(function (txt) {
            emit({ k: "fetch", url: url, method: method, status: resp.status, req: req, res: clip(txt) });
          }, function () { emit({ k: "fetch", url: url, method: method, status: resp.status, req: req, res: "" }); });
        } catch (e) { emit({ k: "fetch", url: url, method: method, status: resp.status, req: req, res: "" }); }
        return resp;
      });
    };
  }
  var OX = window.XMLHttpRequest;
  if (OX) {
    var op = OX.prototype.open, se = OX.prototype.send;
    OX.prototype.open = function (m, u) { this.__wm = m; this.__wu = u; return op.apply(this, arguments); };
    OX.prototype.send = function (body) {
      var x = this;
      x.addEventListener("load", function () {
        try {
          var rt = "";
          try { rt = (x.responseType === "" || x.responseType === "text") ? x.responseText : "[" + x.responseType + "]"; } catch (e) {}
          emit({ k: "xhr", url: x.__wu, method: x.__wm, status: x.status, req: body ? clip(body) : "", res: clip(rt) });
        } catch (e) {}
      });
      return se.apply(this, arguments);
    };
  }
  var OW = window.WebSocket;
  if (OW) {
    var WS = function (url, protocols) {
      var ws = (protocols !== undefined) ? new OW(url, protocols) : new OW(url);
      emit({ k: "ws", url: url, ev: "open" });
      ws.addEventListener("message", function (e) {
        emit({ k: "ws", url: url, ev: "recv", res: (typeof e.data === "string") ? clip(e.data) : "[binary]" });
      });
      ws.addEventListener("close", function () { emit({ k: "ws", url: url, ev: "close" }); });
      var os = ws.send;
      ws.send = function (d) {
        try { emit({ k: "ws", url: url, ev: "send", req: (typeof d === "string") ? clip(d) : "[binary]" }); } catch (e) {}
        return os.apply(ws, arguments);
      };
      return ws;
    };
    try {
      WS.prototype = OW.prototype;
      WS.CONNECTING = OW.CONNECTING; WS.OPEN = OW.OPEN; WS.CLOSING = OW.CLOSING; WS.CLOSED = OW.CLOSED;
      window.WebSocket = WS;
    } catch (e) {}
  }
})();
