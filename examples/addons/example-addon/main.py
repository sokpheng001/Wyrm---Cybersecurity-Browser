#------------------------------------------------------------------------------
# Example Wyrm add-on. Copy this folder into your profile's addons/ folder
# (Security panel -> Add-ons -> "Open add-ons folder"), enable it under
# Security -> Add-ons, then restart Wyrm.
#
# An add-on is any folder with a manifest.json and an entry module (main.py)
# that defines register(ctx). See ADDONS.md for the full API.
#------------------------------------------------------------------------------
from PySide6.QtWidgets import QLabel, QPushButton, QVBoxLayout, QWidget


def register(ctx):
    # 1) Rewrite requests: add a header to every request flowing through the proxy.
    def tag(req):
        req["headers"].append(("X-Wyrm-Addon", ctx.name))
    ctx.on_request(tag)

    # 2) Watch responses passively: count pages served without a Content-Security-Policy.
    def check(flow):
        headers = {k.lower(): v for k, v in flow.get("resp_headers", [])}
        if "content-security-policy" not in headers:
            ctx.storage["no_csp"] = ctx.storage.get("no_csp", 0) + 1
            ctx.save()
            ctx.log(f"no CSP: {flow.get('url')}")
    ctx.on_response_observed(check)

    # 3) Add a tab to the Security panel.
    w = QWidget()
    v = QVBoxLayout(w)
    v.addWidget(QLabel("<b>Example add-on</b><br>Adds <code>X-Wyrm-Addon</code> to requests and "
                       "counts pages with no Content-Security-Policy."))
    btn = QPushButton("Show CSP-missing count")
    btn.clicked.connect(lambda: ctx.toast(f"Pages seen without a CSP: {ctx.storage.get('no_csp', 0)}"))
    v.addWidget(btn)
    v.addStretch(1)
    ctx.add_tab("Example", w)

    ctx.log("example add-on loaded")
