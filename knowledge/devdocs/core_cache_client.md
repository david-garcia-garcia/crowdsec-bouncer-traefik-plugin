# DecisionStore cache

## Language

**DecisionStore**:
A reclaim value that owns one `pkg/cache.Client` (memory TTL map or Redis-protocol pool). Isolation is by store key: CrowdSec cursor `SessionHex` plus Redis store parameters. Two `lapi.Client` incarnations that share that key share remediations.
_Avoid_: process `ttl_map`, shared `var cache`, isolated-per-Client map, `sync.Once`, utilities `reclaim`

**Typed bag**:
`pkg/cache` as `Set` of a string or a `uint32` machine word, `Get`/`GetMany` of strings, and `GetInt` of a `uint32`. Cache does not name kind, origin, Packed, Leftover, or remediation.
_Avoid_: `Stored`, `SetRemediation`, `GetManyStored`, `ParsePackedOriginID`, a MemoryBackend remediation switch, `\x1e`

**Origin intern**:
A `pkg/intern.Table` on one DecisionStore incarnation. Append-only name→`uint16`. Index 0 is unused. `OriginName` is lock-free. Overflow does not wrap.
_Avoid_: package `var`, a table shared across store reclaim keys, inlining intern on DecisionStore

**Packed word**:
A memory `uint32` of `kind[0]` in the low byte and intern id in the upper bits. Overflow, Redis, live/none, and range-index stay leftover strings instead.
_Avoid_: packing inside `pkg/cache`, intern ids in the range-index blob, wrapping intern ids

## Overview

Open a DecisionStore with `lapi.OpenDecisionStore` on the same Traefik `New` ctx as `OpenStream` / `OpenLive`. Pass `SessionHex` as Redis `keyPrefix` for every mode. Do not restore a package-level map. Do not Close the cache from `lapi.Client.Close`.

## How to use

- Call `lapi.OpenDecisionStore(ctx, cfg, log)` then `lapi.New(..., store)` (or `OpenStream` / `OpenLive`, which Open the store first).
- Memory: the store owns a private TTL map. Prefix is ignored.
- Redis: prefix is `SessionHex` (cursor), not live `IdentityHex`. Logical keys are the client IP, `scope:value`, and `range-index`; the store writes `prefix:key`. The cache is a typed bag: `Set` a string or a `uint32`, `Get`/`GetMany` strings, `GetInt` a word. Do not put a remediation codec in `pkg/cache`. Ban/captcha/none leftover strings and packed words live on `pkg/decisionscope` plus the DecisionStore intern table. Captcha grace is the gate cookie (`core_plugin_middleware_captcha-gate.md`), not cache keys.
- Same store key → same cache Client. Different Redis hosts (or enabled/password/database/read hosts) isolate.
- `decisionScopeHeaders` and poller intervals stay off the store key. Stream `scopes=` and the store header-scope filter are the live-router union (`core_plugin_lapi_scope-union.md`).
- `cache.Client.Acquire` is the stream lease (Redis Eval or memory mutex). Do not Get-then-Set `updated`.
- Memory stream/alone Ip and header writes `Pack` then `Set` a word when intern succeeds. `GetInt` misses a leftover string; then `Get` that string. Range-index stays leftover/bare strings via `Set`. Redis, live/none, and intern overflow keep leftover `Set`.
- Origin intern is a `pkg/intern.Table` field on `DecisionStore`. Not a package var. Not shared across store reclaim keys. `OriginName` is a thin `Table.Name` forward.
- `cache.Client.Close()` drains Redis idle pools. Call it only from the store’s reclaim Close hook. Memory clients are a no-op. Safe to call more than once (`SimpleRedis.Close` CAS).

## Pattern snippet

```go
store, err := lapi.OpenDecisionStore(ctx, cfg, log)
lapiClient, err := lapi.New(cfg, log, pluginVersion, store)
_ = lapiClient.Cache()
```

## Key files

- `pkg/lapi/decisionstore.go`
- `pkg/intern/table.go`
- `pkg/cache/cache.go`
- `pkg/cache/acquire.go`
- `pkg/lapi/session.go`

## Gotchas

- Match miss and unreachable with `errors.Is(err, cache.ErrMiss)` / `errors.Is(err, cache.ErrUnreachable)`. Do not string-compare `err.Error()` to `CacheMiss` / `CacheUnreachable`.
- SessionHex and store Redis params stay. Existing Redis keys stay reachable. Changing the Client Open string does not migrate Redis keys.
- Real-stack restart cases still need distinct `X-Forwarded-For` per TTL, because an Ip key is still the client IP inside one store. Header-scope and `range-index` keys are extra keys on the same cache Client.
- `lapi.Client.Close` / `Sleep` must not Close the shared store.
- Stream store-write TTL is `int64(duration.Seconds())` with no clamp; a sub-second CrowdSec duration becomes `0`.
- Live and none writes use `liveCacheTTL` (substitute `defaultDecisionSeconds` when `durationSecond<=0`). Stream must not use `liveCacheTTL`.
