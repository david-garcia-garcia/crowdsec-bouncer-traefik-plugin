# DecisionStore cache

## Language

**DecisionStore**:
A reclaim value that owns one `pkg/cache.Client` (memory TTL map or Redis-protocol pool) and one session-scoped origin dictionary. Isolation is by store key: CrowdSec cursor `SessionHex` plus Redis store parameters. Two `lapi.Client` incarnations that share that key share remediations and intern ids.
_Avoid_: process `ttl_map`, shared `var cache`, isolated-per-Client map, `sync.Once`, utilities `reclaim`

## Overview

Open a DecisionStore with `lapi.OpenDecisionStore` on the same Traefik `New` ctx as `OpenStream` / `OpenLive`. Pass `SessionHex` as Redis `keyPrefix` for every mode. Do not restore a package-level map. Do not Close the cache from `lapi.Client.Close`.

## How to use

- Call `lapi.OpenDecisionStore(ctx, cfg, log)` then `lapi.New(..., store)` (or `OpenStream` / `OpenLive`, which Open the store first).
- Memory: the store owns a private TTL map and the origin dictionary (`core_cache_client_origin-dictionary.md`). Prefix is ignored. Ip/header remediations MAY be a packed kind-plus-origin-id word. Lease and `range-index` blob stay strings.
- Redis: prefix is `SessionHex` (cursor), not live `IdentityHex`. Logical keys are the client IP, `scope:value`, and `range-index`; the store writes `prefix:key`. Payloads are opaque strings (`RemediationWithOrigin`). Ban/captcha/none codes live on `pkg/decisionscope`. Captcha grace is the gate cookie (`core_plugin_middleware_captcha-gate.md`), not cache keys.
- Same store key → same cache Client. Different Redis hosts (or enabled/password/database/read hosts) isolate.
- `decisionScopeHeaders` and poller intervals stay off the store key. Stream `scopes=` and the store header-scope filter are the live-router union (`core_plugin_lapi_scope-union.md`).
- `cache.Client.Acquire` is the stream lease (Redis Eval or memory mutex). Do not Get-then-Set `updated`.
- `cache.Client.Close()` drains Redis idle pools. Call it only from the store’s reclaim Close hook. Memory clients are a no-op. Safe to call more than once (`SimpleRedis.Close` CAS).

## Pattern snippet

```go
store, err := lapi.OpenDecisionStore(ctx, cfg, log)
lapiClient, err := lapi.New(cfg, log, pluginVersion, store)
_ = lapiClient.Cache()
```

## Key files

- `pkg/lapi/decisionstore.go`
- `pkg/lapi/origindict.go`
- `pkg/cache/cache.go`
- `pkg/cache/stored.go`
- `pkg/cache/acquire.go`
- `pkg/lapi/session.go`

## Gotchas

- SessionHex and store Redis params stay. Existing Redis keys stay reachable. Changing the Client Open string does not migrate Redis keys.
- Real-stack restart cases still need distinct `X-Forwarded-For` per TTL, because an Ip key is still the client IP inside one store. Header-scope and `range-index` keys are extra keys on the same cache Client.
- `lapi.Client.Close` / `Sleep` must not Close the shared store.
- Packed origin ids are cache payload on this store. `MetricsReporter` resolves names through the same table and is not a reclaim value.
