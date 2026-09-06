# Redis cache client

## Language

**In-tree SimpleRedis**:
This plugin’s pooled Redis client in `pkg/simpleredis` (`Init`/`Get`/`Set`/`Del`/`MGet`/`Close`, RESP arrays, idle connections).
_Avoid_: published `github.com/maxlerebourg/simpleredis`, v1.0.12 vendor copy

**Redis cache**:
`pkg/cache` `redisCache` when `redisCacheEnabled` is true: one writer plus optional read hosts, each a `*simpleredis.SimpleRedis`.
_Avoid_: local TTL map, mock `serveRedis`

## Overview

Use `pkg/simpleredis` for Redis-protocol GET/SET/DEL/MGET. Hold each client by pointer after `Init` so the pool mutex is not copied. Do not import the published module.

## How to use

- `Client.New(..., isRedis=true, writeHost, readHosts, pass, database, keyPrefix)` inits the writer and each reader. `keyPrefix` is `crowdsecconnection.CachePrefix` (stream/alone session hex, live/none `IdentityHex`) so two Connections on one Redis do not collide unless they share a stream session.
- Request lookup uses `GetMany` (Redis `MGET`, one `nextReader()`): the client IP, optional `range-index`, and each present header-scope key. Prefix each logical key. Missing keys are omitted from the result map.
- Cache keys for remediations are the client IP, `scope:value` for header-mapped scopes, and one `range-index` blob, namespaced by connection identity when Redis is on.
- `SimpleRedis.Close()` drains idle sockets and refuses to pool again. `cache.Client.Close()` closes the writer and every reader. `CrowdsecConnection.Close()` calls that.

## Pattern snippet

```go
r := &simpleredis.SimpleRedis{}
r.Init(host, pass, database)
values, err := r.MGet([]string{key, "range-index"})
```

## Key files

- `pkg/simpleredis/simpleredis.go`
- `pkg/cache/cache.go`

## Gotchas

- Do not copy `SimpleRedis` by value after `Init`.
- After `Close()`, further Get/Set/Del/MGet return `redis:unreachable` and do not dial.
- The mock e2e Redis stand-in must speak RESP arrays; inline GET is leftover compatibility.
- Real-stack Redis-cache e2e uses Dragonfly, not Redis.
- Pass a non-empty `keyPrefix` (connection identity hex) when two Crowdsec backends share one Redis.
