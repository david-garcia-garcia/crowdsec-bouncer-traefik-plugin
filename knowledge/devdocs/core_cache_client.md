# Isolated cache Client

## Language

**Isolated cache**:
One `pkg/cache.Client` store per CrowdsecConnection. Memory is a private TTL map on that Client. Redis keys are prefixed with `IdentityHex` so two Connections on one Redis do not share remediations, captcha grace, or the `"updated"` lease.
_Avoid_: process `ttl_map`, shared `var cache`, bare client-IP Redis keys

## Overview

Construct a new `Client` on each CrowdsecConnection. Pass `crowdsecconnection.IdentityHex(cfg)` as Redis `keyPrefix`. Do not restore a package-level map.

## How to use

- Memory: `Client.New(..., isRedis=false, ..., keyPrefix)` — prefix is ignored; each Client owns a map.
- Redis: pass identity hex as `keyPrefix`. Logical keys stay the client IP; the store writes `prefix:key`.
- Same reclaim key → same Connection → same Client (share-by-identity, not a process dump).
- `Client.Close()` drains Redis idle pools. Call it from `CrowdsecConnection.Close()`. Memory clients are a no-op.

## Pattern snippet

```go
c := &cache.Client{}
c.New(log, redisOn, writeHost, readHosts, pass, database, crowdsecconnection.IdentityHex(cfg))
```

## Key files

- `pkg/cache/cache.go`
- `pkg/crowdsecconnection/identity.go`

## Gotchas

- No migration of existing Redis keys: two Connections that previously shared keys now isolate.
- Real-stack restart cases still need distinct `X-Forwarded-For` per TTL, because the logical key is still the client IP inside one Connection.
