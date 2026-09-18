# LAPI reclaim key

## Language

**Reclaim key**:
The Open key this plugin passes to reclaim for one `lapi.Client`. Stream/alone `SessionKey` is `lapi:stream:` plus `SessionHex` plus a hash of Redis store parameters. Live/none `Key` is `lapi:` plus the same `SessionHex` plus a hash of the identity payload (Redis store params and `MetricsUpdateIntervalSeconds`). `IdentityHex` stays exported; it is not the live Open suffix.
_Avoid_: middleware name, IdentityHex as the stream or live Open key, Bouncer, CrowdsecConnection, AppSec host, StoreKey as the Client string

## Overview

How this plugin keys a reclaimed `lapi.Client`. Spec: `core_plugin_lapi_reclaim-key`. Constructor `ctx` is the reclaim holder. Client address, when this path mentions it, reuses `pkg/ip.GetRemoteIP` (`core_plugin_ip`). Stream `scopes=` is owned by `core_plugin_lapi_scope-union`.

## How to use

- Stream/alone: derive `SessionPrefix` from mode, LAPI scheme/host/path, and lapiKey (CAPI machine+password in alone). `SessionKey` is that prefix plus `hash(storeParamsFrom)`. Call `lapi.OpenStream`.
- Live/none: use `lapi.Key` (`lapi:` + `SessionHex` + identity hash including Redis and `MetricsUpdateIntervalSeconds`). Call `lapi.OpenLive`.
- A second stream `New` for the same cursor plus Redis `Open`s that same key. Stream interval, CAPI scenario, `updateMaxFailure`, backend backoff knobs, and header-map mismatch is silent first-wins for those create-time scalars. A second none/live `New` that differs only on `MetricsUpdateIntervalSeconds` Opens a sibling Client and keeps the same DecisionStore. A different Redis host Opens a different Client and DecisionStore.
- When the previous stream slot is sleeping, the same Redis snapshot `Open`s (Wake, `startup=false`) even if intervals differ. A different Redis host Opens a new key; the sleeper stays until grace Close. Last holder `Sleep`s tickers before grace.
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
- `pkg/lapi/decisionstore.go`

## Gotchas

- Do not put middleware name, `next`, templates, trusted IPs, Enabled, AppSec host/key/TLS/body limit, LAPI failure action, Redis fail-closed, live-cache TTL, `StreamStartupBlock`, HTTP timeout, CAPI scenarios, `updateMaxFailure`, backend backoff knobs, `decisionScopeHeaders`, or the three LAPI TLS fields in the Client Open key. Stream `SessionKey` also omits intervals. Live/none `Key` keeps `MetricsUpdateIntervalSeconds` so write-once tickers stay per Client.
- Redis host/auth/db/enabled and `RedisCacheReadHosts` stay on the Client key (same Redis family as `StoreKey`). Do not reuse the `decisionstore:` prefix. Do not put intervals on `StoreKey`.
- DecisionStore reclaim key is `decisionstore:` + `SessionHex` + Redis params only (`core_cache_client.md`).
- Isolated CrowdSec backends need a second bouncer key (or a different LAPI host), not a second ticker on the same row.
- Upgrade: SessionHex and store Redis params stay. Existing Redis keys stay reachable. Only the in-process Client Open string changes. No Redis key migration.
- Do not parse `RemoteAddr` for client address. Do not fold Open-key composition into `core_plugin_lapi_connection` (that leaf is replaceable transport).
- Do not call `Peek` / `PeekLivePrefix` to find a sibling or retitle a sleeper.
