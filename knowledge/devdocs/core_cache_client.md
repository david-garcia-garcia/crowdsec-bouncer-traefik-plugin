# DecisionStore cache

## Language

**DecisionStore**:
A reclaim value that owns one `pkg/cache.Client` (memory TTL map or Redis-protocol pool). Isolation is by store key: CrowdSec cursor `SessionHex` plus Redis store parameters. Two `lapi.Client` incarnations that share that key share remediations.
_Avoid_: process `ttl_map`, shared `var cache`, isolated-per-Client map, `sync.Once`, utilities `reclaim`

## Overview

Open a DecisionStore with `lapi.OpenDecisionStore` on the same Traefik `New` ctx as `OpenStream` / `OpenLive`. Pass `SessionHex` as Redis `keyPrefix` for every mode. Do not restore a package-level map. Do not Close the cache from `lapi.Client.Close`.

## How to use

- Call `lapi.OpenDecisionStore(ctx, cfg, log)` then `lapi.New(..., store)` (or `OpenStream` / `OpenLive`, which Open the store first).
- Memory: the store owns a private TTL map. Prefix is ignored.
- Redis: prefix is `SessionHex` (cursor), not live `IdentityHex`. Logical keys are the client IP, `scope:value`, and `range-index`; the store writes `prefix:key`. Payloads are opaque strings. Ban/captcha/none codes live on `pkg/decisionscope`. Captcha grace is the gate cookie (`core_plugin_middleware_captcha-gate.md`), not cache keys.
- Same store key → same cache Client. Different Redis hosts (or enabled/password/database/read hosts) isolate.
- `decisionScopeHeaders` and poller intervals stay off the store key. Stream `scopes=` and the store header-scope filter are the live-router union (`core_plugin_lapi_scope-union.md`).
- `cache.Client.Acquire` is the stream lease (Redis Eval or memory mutex). Do not Get-then-Set `updated`.
- A write lifetime of zero or less is not a write. `Set` returns without touching the backend and `Acquire` returns `false` plus `cache:bad-ttl`. Compute a positive TTL before you call, and do not read a silent `Set` as "cached".
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

- Match miss and unreachable with `errors.Is(err, cache.ErrMiss)` / `errors.Is(err, cache.ErrUnreachable)`. Do not string-compare `err.Error()` to `CacheMiss` / `CacheUnreachable`.
- SessionHex and store Redis params stay. Existing Redis keys stay reachable. Changing the Client Open string does not migrate Redis keys.
- A non-positive TTL used to mean two different things. In memory it stored an entry that **never expires**, so a cached ban outlived its decision; on Redis it was rejected outright and logged an error per call. Both are now a no-op, which is why the memory backend no longer has a way to write a permanent entry at all.
- Real-stack restart cases still need distinct `X-Forwarded-For` per TTL, because an Ip key is still the client IP inside one store. Header-scope and `range-index` keys are extra keys on the same cache Client.
- `lapi.Client.Close` / `Sleep` must not Close the shared store.
- Stream store-write TTL is `int64(duration.Seconds())` with no clamp; a sub-second CrowdSec duration becomes `0`.
- Live and none writes use `liveCacheTTL` (substitute `defaultDecisionSeconds` when `durationSecond<=0`). Stream must not use `liveCacheTTL`.
