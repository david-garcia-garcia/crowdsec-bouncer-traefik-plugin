# LAPI reclaim key

## Language

**Reclaim key**:
The Open key this plugin passes to reclaim for one `lapi.Client`. Stream/alone `SessionKey` is session prefix plus first-wins settings hash. Live/none `Key` is LAPI connection identity that drops the same per-router and transport fields.
_Avoid_: middleware name, IdentityHex as the stream Open key, Bouncer, CrowdsecConnection, AppSec host

## Overview

How this plugin keys a reclaimed `lapi.Client`. Spec: `core_plugin_lapi_reclaim-key`. Constructor `ctx` is the reclaim holder. Client address, when this path mentions it, reuses `pkg/ip.GetRemoteIP` (`core_plugin_ip`).

## How to use

- Stream/alone: derive `SessionPrefix` from mode, LAPI scheme/host/path, and lapiKey (CAPI machine+password in alone). `SessionKey` is that prefix plus the remaining first-wins settings hash. Call `lapi.OpenStream`.
- Live/none: use `lapi.Key` from LAPI connection identity (no stream cursor, no AppSec fields). Call `lapi.OpenLive`.
- On a second live `New` for the same session prefix with a different remaining hash, `PeekLivePrefix` and warn-and-wire to the live slot (first `New` wins those knobs; INFO `ignored`). A `New` that differs only on dropped fields reuses the same key and Client.
- When the previous slot is sleeping, a different settings snapshot `Open`s a new key; the same snapshot Wakes (`startup=false`). Last holder `Sleep`s tickers before grace.
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

## Gotchas

- Do not put middleware name, `next`, templates, trusted IPs, Enabled, AppSec host/key/TLS/body limit, LAPI failure action, Redis fail-closed, live-cache TTL, `StreamStartupBlock`, HTTP timeout, or the three LAPI TLS fields in the reclaim key.
- Remaining first-wins hash fields are intervals, Redis host/auth/db/enabled, `updateMaxFailure`, CAPI scenarios, and `decisionScopeHeaders`.
- Isolated CrowdSec backends need a second bouncer key (or a different LAPI host), not a second ticker on the same row.
- Do not parse `RemoteAddr` for client address. Do not fold Open-key composition into `core_plugin_lapi_connection` (that leaf is replaceable transport).
