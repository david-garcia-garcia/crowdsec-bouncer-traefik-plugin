# Redis cache client

## Language

**Utilities SimpleRedis**:
The vendored Redis client from `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis` (`New`/`Get`/`Set`/`Del`/`MGet`/`Close`, RESP arrays, idle connections).
_Avoid_: `pkg/simpleredis`, published `github.com/maxlerebourg/simpleredis`

**Redis cache**:
`pkg/cache` `redisCache` when `redisCacheEnabled` is true: one writer plus optional read hosts, each a `*simpleredis.SimpleRedis`.
_Avoid_: local TTL map, mock `serveRedis`

## Overview

Use the utilities SimpleRedis module for Redis-protocol GET/SET/DEL/MGET. Construct with `simpleredis.New` (dial 2s, command 1s). Hold each client by pointer so the pool mutex is not copied. Do not import the published maxlerebourg module.

## How to use

- `Client.New(..., isRedis=true, writeHost, readHosts, pass, database, keyPrefix)` builds the writer and each reader via `simpleredis.New`. `keyPrefix` is `SessionHex` for every mode so two LAPI Clients that share a DecisionStore also share keys.
- Request lookup uses `GetMany` (Redis `MGET`, one `nextReader()`): the client IP, optional `range-index`, and each present header-scope key. Prefix each logical key. Missing keys are omitted from the result map.
- Cache keys for remediations are the client IP, `scope:value` for header-mapped scopes, and one `range-index` blob, namespaced by the store’s `SessionHex` `keyPrefix` when Redis is on.
- Commands pass `context.Background()` (the cache API has no request context).
- `SimpleRedis.Close()` drains idle sockets and refuses to pool again. Safe to call more than once (CAS). `cache.Client.Close()` closes the writer and every reader. Only the DecisionStore reclaim Close hook calls that.
- Stream lease acquire is `cache.Client.Acquire`: one `Eval` (`EVALSHA` then `EVAL` on NOSCRIPT) on the writer plus prefix. Do not Get-then-Set. Do not add a SetNX wrapper.

## Pattern snippet

```go
client, err := simpleredis.New(simpleredis.Config{
	Host: host, Pass: pass, Database: database,
	DialTimeout: 2 * time.Second, CommandTimeout: time.Second,
})
values, err := client.MGet(context.Background(), []string{key, "range-index"})
```

## Key files

- `pkg/cache/cache.go`
- `pkg/cache/acquire.go`
- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis/`

## Gotchas

- Do not copy `SimpleRedis` by value after `New`.
- After `Close()`, further Get/Set/Del/MGet return unreachable and do not dial.
- Match miss/unreachable with `IsMiss` / `IsUnreachable` (legacy `redis:*` strings still exist).
- The mock e2e Redis stand-in must speak RESP arrays; inline GET is leftover compatibility.
- Real-stack Redis-cache e2e uses Dragonfly, not Redis.
- Pass a non-empty `keyPrefix` (`SessionHex`) when two LAPI Clients share one Redis.
- Do not take utilities zero-Config dial/command defaults (200ms/900ms).
