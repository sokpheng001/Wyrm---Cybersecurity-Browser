# Wyrm add-on examples

Reference add-ons showing the Wyrm add-on API. Each is a folder with a `manifest.json`
(`{name, version, entry, author, description, permissions}`) and an entry module (default
`main.py`) exposing a top-level `register(ctx)`.

## Install an example

1. Find your Wyrm data directory (per-user app data; the same place the profile lives).
2. Copy the example folder into `addons/` there, e.g. `addons/permissions-policy-check/`.
3. Open Wyrm → **Security → Add-ons**, find the add-on, and enable it. Add-ons run in-process
   as trusted Python, so only enable ones you've read.

## What `ctx` gives an add-on

- `ctx.on_request(fn)` / `ctx.on_response(fn)` — rewrite live proxy traffic (needs the intercepting proxy on).
- `ctx.on_response_observed(fn)` — watch responses passively.
- `ctx.add_scan_check(check)` — register a custom active/passive scanner check (see `permissions-policy-check`).
- `ctx.add_tab(name, widget)` — add a tab to the Security panel.
- `ctx.add_finding(**kwargs)`, `ctx.toast(msg)`, `ctx.log(msg)`.
- `ctx.storage` (dict) + `ctx.save()` — small persistent, per-add-on storage (stored 0600).

## Examples

- **permissions-policy-check** — registers a scanner check that flags any page served without a
  `Permissions-Policy` header. Shows the minimal shape of a custom check and how it reuses the
  engine's already-fetched response (`baseline`) instead of sending extra requests.
