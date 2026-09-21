# LAPI live-router scope union

## Language

**Live-router scope union**:
The Client-owned merge of every LAPI opener’s normalized `lapiScopeHeaders` map registered at `OpenStream`. Stream `scopes=` and the stream store filter snapshot this union. Bouncing subscribers do not register. Write-once `lapiScopeHeaders` is first-create residue when no opener is registered yet.
_Avoid_: PeekLivePrefix sibling, mutating the write-once map, package global, first-wins settings hash

## Overview

How a shared stream `lapi.Client` builds `scopes=` and the stream store filter from LAPI openers only. Spec: `core_plugin_lapi_scope-union`. Write-once `lapiScopeHeaders` stays the first-create residue; it is not the live union.

## How to use

- After a successful `OpenStream` bind, register this opener’s `New` ctx and normalized `lapiScopeHeaders` on the Client. Subscribers must not register.
- Unregister when that ctx is Done (`context.AfterFunc`). Holder is Traefik `New` ctx.
- `streamQuery` and `storeStreamDecision` snapshot the union under the existing Client mutex.
- CAPI (alone) still omits `scopes=`. Live/none still pass scopes per `LiveLookup`.
- Do not mutate write-once `lapiScopeHeaders`. Do not use `atomic.Pointer[T]`, `sync.Once`, or a package global.

## Pattern snippet

```go
client.registerLiveHeaderScopes(ctx, decisionscope.NormalizeLapiScopeHeaders(cfg.LapiScopeHeaders))
query := client.streamQuery()
```

## Key files

- `pkg/lapi/liveheaderscopes.go`
- `pkg/lapi/session.go`
- `pkg/lapi/client_decisions.go`

## Gotchas

- Growing the union does not send `startup=true`. A newly added scope misses decisions already past the CrowdSec cursor until a later incarnation `startup=true`.
- Shrinking the union does not sweep header-scope cache keys. Stale Country/AS keys expire with TTL or die with the store incarnation.
- When no live holder is registered yet (create-time first poll), the snapshot falls back to write-once `lapiScopeHeaders`.
- Empty live maps stream only `ip,range`.
