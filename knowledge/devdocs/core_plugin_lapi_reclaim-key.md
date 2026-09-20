# LAPI reclaim key

## Language

**Reclaim key**:
The Open key this plugin passes to reclaim for one `lapi.Client`. Stream/alone `SessionKey` is `lapi:stream:` plus `SessionHex` (mode + LAPI scheme/host/path + lapiKey, CAPI in alone). Live/none `Key` is `lapi:` plus the same `SessionHex` plus a hash of the identity payload (Redis store params and `MetricsUpdateIntervalSeconds`). `IdentityHex` stays exported; it is not the live Open suffix.
_Avoid_: middleware name, outbound IP, IdentityHex as the stream or live Open key, Bouncer, CrowdsecConnection, AppSec host, StoreKey as the Client string, Redis hash on the stream Open key

## Overview

How this plugin keys a reclaimed `lapi.Client`. Spec: `core_plugin_lapi_reclaim-key`. Constructor `ctx` is the reclaim holder. Client address, when this path mentions it, reuses `pkg/ip.GetRemoteIP` (`core_plugin_ip`). Stream `scopes=` is owned by `core_plugin_lapi_scope-union`.

## How to use

- Stream/alone: derive `SessionHex` from mode, LAPI scheme/host/path, and lapiKey (CAPI machine+password in alone). `SessionKey` is `lapi:stream:` plus that hex. Call `lapi.OpenStream`.
- Live/none: use `lapi.Key` (`lapi:` + `SessionHex` + identity hash including Redis and `MetricsUpdateIntervalSeconds`). Call `lapi.OpenLive`.
- A second stream `New` for the same LAPI session `Open`s that same key. Redis, interval, CAPI scenario, `metricsUpdateIntervalSeconds`, and `updateMaxFailure` mismatch is first-wins with WARN (ignored field names, distinct holder middleware names, isolation needs a second bouncer API key). A second none/live `New` that differs only on `MetricsUpdateIntervalSeconds` Opens a sibling Client. A different Redis host Opens a different live/none Client; stream Redis disagreement reuses the stream Client.
- When the previous stream slot is sleeping, `Open` (Wake, `startup=false`) even if Redis or intervals differ. Last holder `Sleep`s tickers before grace. A Redis YAML change on Wake keeps the live store and WARNs; no memory↔Redis migrate.
- Register this constructor ctx → Traefik `name` after a successful Open (same shape as live header-scope registration). Unregister on ctx Done. Do not store a single `ownerName`.
- Leave `HTTPTimeoutSeconds` and the three inherit timeout knobs (`CrowdsecLapiHTTPTimeoutSeconds`, `CrowdsecAppsecHTTPTimeoutSeconds`, `CaptchaSiteverifyHTTPTimeoutSeconds`) out of `SessionKey`, live `Key`, and `IdentityHex`. Reuse `streamSession` / `identity`. Do not add timeout knobs or effective seconds to those payloads.
- Pass `reclaim.Hooks` for Sleep/Wake/Close. An unreclaimed `lapi.Client` waits `ProcessGrace` 30s.

## Pattern snippet

```go
key := lapi.SessionKey(cfg)
lapiClient, err := lapi.OpenStream(ctx, cfg, log, name, pluginVersion)
```

## Key files

- `pkg/lapi/session.go`
- `pkg/lapi/identity.go`
- `pkg/lapi/client.go`
- `pkg/lapi/sessionresidue.go`
- `pkg/lapi/liveholders.go`
- `pkg/lapi/decisionstore.go` (`StoreKey` helper, `newChildStore`)
- `pkg/decisionstore/store.go`

## Gotchas

- Do not put middleware name, outbound IP, `next`, templates, trusted IPs, Enabled, AppSec host/key/TLS/body limit, LAPI failure action, Redis fail-closed, live-cache TTL, `StreamStartupBlock`, `HTTPTimeoutSeconds`, `CrowdsecLapiHTTPTimeoutSeconds`, `CrowdsecAppsecHTTPTimeoutSeconds`, `CaptchaSiteverifyHTTPTimeoutSeconds`, CAPI scenarios, `updateMaxFailure`, `decisionScopeHeaders`, Redis store parameters, or the three LAPI TLS fields in the stream Client Open key. Stream `SessionKey` also omits intervals. Live/none `Key` keeps Redis and `MetricsUpdateIntervalSeconds` so write-once tickers stay per Client.
- Do not hash Redis into stream `SessionKey`. Isolated CrowdSec backends need a second bouncer key (or a different LAPI host), not a second ticker on the same row.
- `StoreKey` is a composition helper only. Do not Open it as a sibling reclaim value. Redis logical keys stay under `SessionHex`.
- Upgrade: SessionHex stays. Existing Redis keys stay reachable. Only the in-process Client Open string changes. No Redis key migration.
- Do not parse `RemoteAddr` for client address. Do not fold Open-key composition into `core_plugin_lapi_connection` (that leaf is replaceable transport).
- Do not call `Peek` / `PeekLivePrefix` to find a sibling or retitle a sleeper. Do not fail `New` on session-owned mismatch. Do not log `ignored` INFO for those knobs (WARN is this packet).
- WARN must name `redisCachePassword` as a field, never the secret value.
