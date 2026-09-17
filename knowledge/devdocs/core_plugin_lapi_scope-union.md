# LAPI live-router scope union

## Overview

How a shared stream `lapi.Client` builds `scopes=` and the stream store filter from every live constructor that bound it. Spec: `core_plugin_lapi_scope-union`. Write-once `decisionScopeHeaders` stays the first-create residue; it is not the live union.

## How to use

- After a successful `OpenStream` bind, register this `New` ctx and this router’s normalized `decisionScopeHeaders` on the Client.
- Unregister when that ctx is Done (`context.AfterFunc`). Holder is Traefik `New` ctx.
- `streamQuery` and `storeStreamDecision` snapshot the union under the existing Client mutex.
- CAPI (alone) still omits `scopes=`. Live/none still pass scopes per `LiveLookup`.
- Do not mutate write-once `decisionScopeHeaders`. Do not use `atomic.Pointer[T]`, `sync.Once`, or a package global.

## Pattern snippet

```go
client.registerLiveHeaderScopes(ctx, decisionscope.NormalizeDecisionScopeHeaders(cfg.DecisionScopeHeaders))
query := client.streamQuery()
```

## Key files

- `pkg/lapi/liveheaderscopes.go`
- `pkg/lapi/session.go`
- `pkg/lapi/client_decisions.go`

## Gotchas

- Growing the union does not send `startup=true`. A newly added scope misses decisions already past the CrowdSec cursor until a later incarnation `startup=true`.
- Shrinking the union does not sweep header-scope cache keys. Stale Country/AS keys expire with TTL or die with the store incarnation.
- When no live holder is registered yet (create-time first poll), the snapshot falls back to write-once `decisionScopeHeaders`.
- Empty live maps stream only `ip,range`.
