## Why

A Traefik router reload that only changes per-router LAPI policy or LAPI HTTP/TLS still hashes those knobs into the reclaim key, so `New` builds a second `lapi.Client` and pays CrowdSec `startup=true`. Policy belongs on `Bouncer`; TLS/timeout belongs on a replaceable transport on the same Client.

## What Changes

- Move `lapiFailureAction`, `redisUnreachableBlock`, and live-cache TTL onto `Bouncer`. Delete the Client accessors. `LiveLookup` takes the TTL as an argument.
- Drop those three plus `StreamStartupBlock`, HTTP timeout, and the three LAPI TLS fields from stream `streamSettings` / `settingsFrom` and from live/none `identity` / `IdentityHex`.
- Extract LAPI HTTP + auth (including CAPI token) into an unexported `transport` in `client_http.go`, stored on `Client` as `atomic.Value`. After Open, `AdoptTransport(cfg)` Stores the new value and `closeIdle`s the old one. Last `New` wins transport.
- `logInfo` includes session key + `reason`. New INFO lines for transport replace and for a live joiner whose remaining settings differ (`ignored` vs `adopted`). Reclaim table lines stay DEBUG.
- Do not make remaining write-once Client scalars mutable. Do not use `atomic.Pointer[T]`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_instance-reclaim`: settings hash no longer includes per-router policy, `StreamStartupBlock`, HTTP timeout, or LAPI TLS; last `New` adopts transport; Bouncer holds Redis fail-closed and live TTL; joiner INFO `ignored` vs `adopted`.
- `core_plugin_lapi_failure-action`: LAPI failure action is per-router on Bouncer; two routers on one Client MAY disagree.
- `core_plugin_lapi_connection`: LAPI HTTP+auth lives on `transport` (`atomic.Value`); `AdoptTransport` after Open; `LiveLookup` takes TTL; `logInfo` carries session key + `reason`.

## Impact

- `pkg/lapi` (`client.go`, `client_http.go`, `client_live.go`, `client_decisions.go`, `client_stream.go`, `session.go`, `identity.go`, tests).
- `pkg/bouncer/bouncer.go` request path (failure action, Redis fail-closed, live TTL).
- Usage `knowledge/devdocs/core_plugin_middleware.md` Language **Failure action** and identity gotcha after apply (devdocsimpact).
- No **BREAKING** public JSON/YAML keys.
