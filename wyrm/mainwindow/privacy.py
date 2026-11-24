#------------------------------------------------------------------------------
# Wyrm — wyrm/mainwindow/privacy.py
# Part of Wyrm, the privacy & security browser by ByKh R&D Group (https://bykh.org)
# Copyright (c) 2023-present ByKh R&D Group. Licensed under the MIT License (see LICENSE).
# Authors: Oda, Kwan, Kim, Lida, Naly, Buri, Vatanny
#------------------------------------------------------------------------------
"""Shields, HTTPS-Only, encrypted DNS, proxies, Smart Link Check, cosmetic filtering."""
from __future__ import annotations

import json

from PySide6.QtCore import QUrl
from PySide6.QtWebEngineCore import QWebEngineGlobalSettings, QWebEngineScript
from PySide6.QtWidgets import QMessageBox

from .. import linkguard, theme
from ..browser.scripts import COLLECT_JS


class PrivacyMixin:
    """Shields, HTTPS-Only, encrypted DNS, proxies, Smart Link Check, cosmetic filtering. (Mixed into MainWindow.)"""

    # ================================================================ privacy: shields, HTTPS-Only, DNS
    def https_only(self) -> bool:
        return self.settings.value("privacy/https_only", True, type=bool)

    DOH = {"cloudflare": ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
           "quad9": ("Quad9 (malware-blocking)", "https://dns.quad9.net/dns-query"),
           "google": ("Google", "https://dns.google/dns-query"),
           "adguard": ("AdGuard (ad-blocking)", "https://dns.adguard-dns.com/dns-query")}

    def apply_dns(self):
        """Encrypted DNS (DNS-over-HTTPS). Tor windows resolve inside Tor instead."""
        if self.tor:
            return
        mode = self.settings.value("privacy/doh_mode", "secure", type=str)  # off | secure (fallback) | strict
        prov = self.settings.value("privacy/doh_provider", "cloudflare", type=str)
        dm = QWebEngineGlobalSettings.DnsMode()
        if mode == "off":
            dm.secureMode = QWebEngineGlobalSettings.SecureDnsMode.SystemOnly
        else:
            dm.secureMode = (QWebEngineGlobalSettings.SecureDnsMode.SecureOnly if mode == "strict"
                             else QWebEngineGlobalSettings.SecureDnsMode.SecureWithFallback)
            dm.serverTemplates = [self.DOH.get(prov, self.DOH["cloudflare"])[1]]
        QWebEngineGlobalSettings.setDnsMode(dm)

    def _filters_ready(self, ok, engines_):
        if ok and engines_:
            self.shields.engines = engines_
            self.security.shields.refresh()

    def on_blocked(self, view):
        if view is self.current_view() and not self._shield_timer.isActive():
            self._shield_timer.start()

    def _toggle_shields_panel(self):
        """Toolbar Shields button: open the Shields view, or close the whole panel if it's already the one
        showing (so the same button both opens and closes — UX-1). close() also handles the floating case."""
        sec = self.security
        if sec.isVisible() and sec.current_page() is sec.shields:
            sec.close()
        else:
            sec.show_tab("Shields")

    def _update_shield_button(self):
        v = self.current_view()
        n = v.stats.total() if v else 0
        badge = self.shield_badge
        badge.setText(str(n) if n < 1000 else "999+")
        badge.adjustSize()
        bw = max(16, badge.width())
        badge.setGeometry(40 - bw - 1, 2, bw, 16)
        badge.setVisible(n > 0)
        host = v.url().host() if v else ""
        off = bool(host) and not self.shields.site_enabled(host)
        self.b_shield.setToolTip(f"Shields: {n} blocked on this page" + (" (Shields are OFF for this site)" if off else ""))
        if self.security.isVisible() and self.security.current_page() is self.security.shields:
            self.security.shields.refresh()

    def on_link_hovered(self, url: str):
        if not url:
            self.link_bubble.hide()
            return
        cat = None
        if url.startswith("http"):
            host = QUrl(url).host()
            cat = self.shields.check(url, url, "MainFrame", host) if host not in self.shields.malware_allow else None
        v = linkguard.analyze(url, threat=cat if cat in ("malware", "phishing") else None)
        p = theme.PALETTES[self.theme_name]
        color = {"dangerous": p["error"], "suspicious": "#ff832b"}.get(v["verdict"])
        text = url if len(url) < 110 else url[:107] + "…"
        if color:
            label = "Dangerous link" if v["verdict"] == "dangerous" else "Suspicious link"
            self.link_bubble.setText(f"<b style='color:{color}'>{label}:</b> {v['reasons'][0]}<br>"
                                     f"<span style='color:{p['muted']}'>{text}</span>")
        else:
            self.link_bubble.setText(text)
        self.link_bubble.adjustSize()
        self.link_bubble.move(8, self.stack.height() - self.link_bubble.height() - 8)
        self.link_bubble.show()
        self.link_bubble.raise_()

    def show_link_check(self, url: str):
        cat = None
        if url.startswith("http"):
            host = QUrl(url).host()
            cat = self.shields.check(url, url, "MainFrame", host) if host not in self.shields.malware_allow else None
        v = linkguard.analyze(url, threat=cat if cat in ("malware", "phishing") else None)
        icon = {"dangerous": QMessageBox.Icon.Critical, "suspicious": QMessageBox.Icon.Warning}.get(
            v["verdict"], QMessageBox.Icon.Information)
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle("Smart Link Check")
        box.setText({"dangerous": "This link looks dangerous.", "suspicious": "This link looks suspicious.",
                     "safe": "No warning signs found."}[v["verdict"]])
        box.setInformativeText(url + ("\n\n• " + "\n• ".join(v["reasons"]) if v["reasons"] else ""))
        box.exec()

    # ================================================================ per-page features
    def _apply_cosmetics(self, view):
        """Element hiding: list-based selectors for this URL + generic class/id selectors found on the page."""
        url = view.url().toString()
        host = view.url().host()
        if not url.startswith("http") or not self.shields.site_enabled(host):
            return
        css = self.shields.cosmetic_css(url)

        def got(res, v=view, css=css, url=url):
            try:
                d = json.loads(res) if isinstance(res, str) else {}
            except ValueError:
                d = {}
            full = css + self.shields.generic_css(d.get("classes", []), d.get("ids", []), url)
            if full:
                v.page().runJavaScript(
                    "(function(c){let s=document.getElementById('__hb_hide');if(!s){s=document.createElement('style');"
                    "s.id='__hb_hide';(document.head||document.documentElement).appendChild(s);}s.textContent=c;})("
                    + json.dumps(full) + ")", QWebEngineScript.ScriptWorldId.ApplicationWorld)
            yt = int(d.get("yt") or 0)
            if yt > v.stats.counts.get("youtube", 0):
                v.stats.counts["youtube"] = yt
                self.on_blocked(v)
        view.page().runJavaScript(COLLECT_JS, QWebEngineScript.ScriptWorldId.MainWorld, got)

    def _check_popup(self, view):
        """Close pop-ups/pop-unders whose first URL is an ad, tracker or threat."""
        url = view.url().toString()
        if not url.startswith("http"):
            return
        cat = self.shields.check_popup(url)
        if cat:
            opener = self.current_view()
            i = self._index_of(view)
            if i >= 0 and self.tabbar.count() > 1:
                self._remove_tab(i)
            target = opener if opener is not view else self.current_view()
            if target:
                target.stats.counts["popups"] += 1
                target.stats.blocked.append(("popup", url, "Popup"))
                self.shields.count()
                self.on_blocked(target)
            self.toast(f"Blocked a pop-up ({cat}): {QUrl(url).host()}")

    def proxies(self):
        if self.tor:  # everything the browser itself fetches also goes through Tor
            p = f"socks5h://127.0.0.1:{self.tor.socks_port}"
            return {"http": p, "https": p}
        s = self.settings
        if not s.value("proxy/enabled", False, type=bool):
            return None
        p = f"http://{s.value('proxy/host', '127.0.0.1')}:{s.value('proxy/port', 8080, type=int)}"
        return {"http": p, "https": p}

    def verify_tls(self) -> bool:
        s = self.settings
        return not (s.value("proxy/enabled", False, type=bool) and s.value("proxy/insecure", False, type=bool))
