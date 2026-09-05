# Redis cache client

## Language

**In-tree SimpleRedis**:
The pooled Redis client copied into `pkg/simpleredis` from simpleredis PR #8 (`Init`/`Get`/`Set`/`Del`/`MGet`, RESP arrays, idle connections).
_Avoid_: published `github.com/maxlerebourg/simpleredis`, v1.0.12 vendor copy

**Redis cache**:
`pkg/cache` `redisCache` when `redisCacheEnabled` is true: one writer plus optional read hosts, each a `*simpleredis.SimpleRedis`.
_Avoid_: local TTL map, mock `serveRedis`

## Overview

Use `pkg/simpleredis` for Redis-protocol GET/SET/DEL. Hold each client by pointer after `Init` so the pool mutex is not copied. Do not import the published module.

## How to use

- `Client.New(..., isRedis=true, writeHost, readHosts, pass, database)` inits the writer and each reader.
- One key per request: `Get`/`Set`/`Del`. `MGet` exists on the package for later multi-key reads.
- Cache keys for remediations are the client IP Traefik already resolved.

## Pattern snippet

```go
r := &simpleredis.SimpleRedis{}
r.Init(host, pass, database)
value, err := r.Get(key)
```

## Key files

- `pkg/simpleredis/simpleredis.go`
- `pkg/cache/cache.go`
- `pkg/simpleredis/SOURCE`

## Gotchas

- Do not copy `SimpleRedis` by value after `Init`.
- The mock e2e Redis stand-in must speak RESP arrays; inline GET is leftover compatibility.
- Real-stack Redis-cache e2e uses Dragonfly, not Redis.
