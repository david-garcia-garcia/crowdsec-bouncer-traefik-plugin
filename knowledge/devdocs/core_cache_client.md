# DecisionStore cache

## Language

**DecisionStore**:
A reclaim value that owns one `pkg/cache.Client` (memory TTL map or Redis-protocol pool). Isolation is by store key: CrowdSec cursor `SessionHex` plus Redis store parameters. Two `lapi.Client` incarnations that share that key share remediations.
_Avoid_: process `ttl_map`, shared `var cache`, isolated-per-Client map, `sync.Once`, utilities `reclaim`

**Typed bag**:
`pkg/cache` as string `Set`/`Get`/`GetMany` plus `SetInt`/`GetInt` of a `uint32`. Cache does not name kind, origin, Packed, Leftover, or remediation.
_Avoid_: `Stored`, `SetRemediation`, `GetManyStored`, `ParsePackedOriginID`, a MemoryBackend remediation switch, `\x1e`

**Origin intern**:
An append-only name→`uint16` table on one DecisionStore incarnation. Index 0 is unused. `OriginName` is lock-free. Overflow does not wrap.
_Avoid_: package `var`, a table shared across store reclaim keys, `atomic.Pointer[T]`

**Packed word**:
A memory `uint32` of `kind[0]` in the low byte and intern id in the upper bits. Overflow, Redis, and live/none stay leftover strings instead.
_Avoid_: packing inside `pkg/cache`, wrapping intern ids

## Overview

Open a DecisionStore with `lapi.OpenDecisionStore` on the same Traefik `New` ctx as `OpenStream` / `OpenLive`. Pass `SessionHex` as Redis `keyPrefix` for every mode. Do not restore a package-level map. Do not Close the cache from `lapi.Client.Close`.

## How to use

- Call `lapi.OpenDecisionStore(ctx, cfg, log)` then `lapi.New(..., store)` (or `OpenStream` / `OpenLive`, which Open the store first).
- Memory: the store owns a private TTL map. Prefix is ignored.
- Redis: prefix is `SessionHex` (cursor), not live `IdentityHex`. Logical keys are the client IP, `scope:value`, and `range-index`; the store writes `prefix:key`. The cache is a typed bag: `Set`/`Get`/`GetMany` for strings and `SetInt`/`GetInt` for a `uint32` machine word. Do not put a remediation codec in `pkg/cache`. Ban/captcha/none leftover strings and packed words live on `pkg/decisionscope` plus the DecisionStore intern table. Captcha grace is the gate cookie (`core_plugin_middleware_captcha-gate.md`), not cache keys.
- Same store key → same cache Client. Different Redis hosts (or enabled/password/database/read hosts) isolate.
- `decisionScopeHeaders` and poller intervals stay off the store key. Stream `scopes=` and the store header-scope filter are the live-router union (`core_plugin_lapi_scope-union.md`).
- `cache.Client.Acquire` is the stream lease (Redis Eval or memory mutex). Do not Get-then-Set `updated`.
- Memory stream/alone Ip and header writes `SetInt` a packed word when intern succeeds. `GetInt` misses a leftover string; then `Get` that string. Range-index stays a string blob (`Set`). Redis, live/none, and intern overflow keep leftover `Set`.
- Origin intern is a field on `DecisionStore` (append-only name→`uint16`, lock-free `OriginName`). Not a package var. Not shared across store reclaim keys.
- `cache.Client.Close()` drains Redis idle pools. Call it only from the store’s reclaim Close hook. Memory clients are a no-op. Safe to call more than once (`SimpleRedis.Close` CAS).

## Pattern snippet

```go
store, err := lapi.OpenDecisionStore(ctx, cfg, log)
lapiClient, err := lapi.New(cfg, log, pluginVersion, store)
_ = lapiClient.Cache()
```

## Key files

- `pkg/lapi/decisionstore.go`
- `pkg/cache/cache.go`
- `pkg/cache/acquire.go`
- `pkg/lapi/session.go`

## Gotchas

- SessionHex and store Redis params stay. Existing Redis keys stay reachable. Changing the Client Open string does not migrate Redis keys.
- Real-stack restart cases still need distinct `X-Forwarded-For` per TTL, because an Ip key is still the client IP inside one store. Header-scope and `range-index` keys are extra keys on the same cache Client.
- `lapi.Client.Close` / `Sleep` must not Close the shared store.
