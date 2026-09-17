# Isolated cache Client

## Language

**Isolated cache**:
One `pkg/cache.Client` store per LAPI Client. Memory is a private TTL map on that Client. Redis keys are prefixed with `CachePrefix`: stream/alone use the LAPI URL+key session hex so warn-and-wire shares remediations; live/none use `IdentityHex`.
_Avoid_: process `ttl_map`, shared `var cache`, bare client-IP Redis keys

## Overview

Construct a new `Client` on each LAPI Client. Pass `lapi.CachePrefix(cfg)` as Redis `keyPrefix`. Do not restore a package-level map.

## How to use

- Memory: `Client.New(..., isRedis=false, ..., keyPrefix)` — prefix is ignored; each Client owns a map.
- Redis: pass `lapi.CachePrefix(cfg)` as `keyPrefix` (stream/alone session hex, live/none `IdentityHex`). Logical keys are the client IP, `scope:value`, and `range-index`; the store writes `prefix:key`. Payloads are opaque strings. Ban/captcha/none codes live on `pkg/decisionscope`. Captcha grace-done (`d`) lives on `pkg/captcha`.
- Same reclaim key → same LAPI Client → same cache Client (share-by-identity, not a process dump).
- `Client.Close()` drains Redis idle pools. Call it from `lapi.Client.Close()`. Memory clients are a no-op.

## Pattern snippet

```go
c := &cache.Client{}
c.New(log, redisOn, writeHost, readHosts, pass, database, lapi.CachePrefix(cfg))
```

## Key files

- `pkg/cache/cache.go`
- `pkg/lapi/identity.go`
- `pkg/lapi/session.go`

## Gotchas

- No migration of existing Redis keys: two LAPI Clients that previously shared keys now isolate.
- Real-stack restart cases still need distinct `X-Forwarded-For` per TTL, because an Ip key is still the client IP inside one LAPI Client. Header-scope and `range-index` keys are extra keys on the same cache Client.
