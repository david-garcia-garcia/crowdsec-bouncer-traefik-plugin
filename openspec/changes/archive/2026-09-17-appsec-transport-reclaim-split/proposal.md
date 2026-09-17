## Why

A Traefik router reload that only changes AppSec TLS or the shared HTTP timeout still hashes those knobs into the AppSec reclaim key, so `New` builds a second `appsec.Client` and throws away a live HTTP pool. PR #62 already stopped that split for LAPI; AppSec still keys the old way.

## What Changes

- Drop AppSec TLS content fields and `HTTPTimeoutSeconds` from AppSec `identity` / `IdentityHex` / `Key`. Keep scheme, host, path, key, and `bodyLimit`.
- Keep per-router AppSec failure action off that key (it already lives on `Bouncer` + `appsec.Policy`).
- Extract AppSec HTTP+auth (client, API key, timeout, AppSec TLS extras) into an unexported `transport` in `pkg/appsec/client_http.go`, stored on `Client` as `atomic.Value`. After `Open` bind, `AdoptTransport(cfg)` last-wins. Idle-close the previous `*http.Client`.
- Do not use `atomic.Pointer[T]`. Do not convert remaining write-once scalars into mutable fields.
- Delete `knowledge/debt/2026-09-17-appsec-captcha-split.md` when the apply lands.
- No **BREAKING** public JSON/YAML keys.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_client`: reclaim key is AppSec URL+key+body limit (not TLS or HTTP timeout); last `New` adopts replaceable HTTP+auth on `atomic.Value`.

## Impact

- `pkg/appsec/` (session identity, Client transport, Query/Close readers, tests).
- `openspec/specs/core_plugin_appsec_client`.
- Usage `knowledge/devdocs/core_plugin_appsec.md` after apply (devdocsimpact).
- This run closes `knowledge/debt/2026-09-17-appsec-captcha-split.md`.
- Do not edit `pkg/lapi/`, `pkg/reclaim/` internals, `openspec/specs/core_plugin_middleware_instance-reclaim`, or `pkg/lapi/client_metrics.go`.
