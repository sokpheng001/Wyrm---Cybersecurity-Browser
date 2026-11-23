# Wyrm Add-ons

Add-ons are Python plugins that extend Wyrm — rewrite live traffic, watch responses, add their own tab, file
findings — in the spirit of Burp BApps and Caido plugins. They run **in-process as trusted code**, so only enable
add-ons you trust (Wyrm shows a warning before enabling one).

## Install an add-on

1. Security panel → **Add-ons** → **Open add-ons folder** (this is `<your profile>/addons/`).
2. Put the add-on's folder inside it (or use **Install from folder…** to copy one in).
3. Back in Security → **Add-ons**, tick it **On** (confirm the trust prompt).
4. **Restart Wyrm** — add-ons load at startup.

An add-on is a folder with a `manifest.json` and an entry module:

```
addons/
  my-addon/
    manifest.json
    main.py
```

### manifest.json

```json
{
  "name": "My Add-on",
  "version": "1.0.0",
  "entry": "main.py",
  "author": "you",
  "description": "what it does",
  "permissions": ["proxy", "ui"]
}
```

### main.py — `register(ctx)`

```python
def register(ctx):
    def tag(req):
        req["headers"].append(("X-My-Addon", "1"))
    ctx.on_request(tag)
```

## The `ctx` API (`AddonContext`)

Traffic hooks need the intercepting proxy to be on (Security → Proxy).

| Call | What it does |
|------|--------------|
| `ctx.on_request(fn)` | `fn(req)` runs before each request is sent. Mutate `req["method"]`, `req["path"]`, `req["headers"]` (list of `(name, value)`), `req["body"]` (bytes). |
| `ctx.on_response(fn)` | `fn(flow)` runs before the page sees the response. Mutate `flow["status"]`, `flow["resp_headers"]`, `flow["resp_body"]` (bytes). |
| `ctx.on_response_observed(fn)` | `fn(flow)` runs after each response (passive; for detection/metrics). |
| `ctx.add_tab(name, widget)` | Add a PySide6 `QWidget` as a tab under **ADD-ONS** in the Security panel. |
| `ctx.add_finding(**kwargs)` | Open Wyrm's "add finding" dialog (needs an engagement). |
| `ctx.toast(msg)` | Show a status-bar message. |
| `ctx.log(msg)` | Append to the add-on's log (Security → Add-ons → Logs). |
| `ctx.storage` / `ctx.save()` | A dict persisted to the add-on's folder as `storage.json`. |
| `ctx.win` | The main window (full access, for advanced use). |
| `ctx.meta` / `ctx.name` / `ctx.id` | The manifest and identifiers. |

### The `req` and `flow` dicts

- **req**: `{"scheme", "host", "port", "method", "path", "headers": [(k, v)…], "body": bytes}`
- **flow**: the above request fields plus `{"url", "status", "reason", "resp_headers": [(k, v)…], "resp_body": bytes, "ms"}`

## Example

A complete example lives in [`examples/addons/example-addon`](examples/addons/example-addon): it tags every
request, counts pages with no Content-Security-Policy, and adds a tab.

## Notes & limits

- Add-ons are trusted code; there is no sandbox. Review `main.py` before enabling.
- Enabling/disabling/installing takes effect **after a restart** (add-ons load at startup).
- A broken add-on is isolated — it can't stop Wyrm from starting; its error shows in Security → Add-ons.
- A multi-file add-on may `import` its own sibling modules (its folder is on `sys.path` while it loads).
