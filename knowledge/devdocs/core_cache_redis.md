# Redis cache client

## Language

**Utilities SimpleRedis**:
The vendored Redis client from `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis` (`New`/`Get`/`Set`/`Del`/`MGet`/`Close`, RESP arrays, idle connections).
_Avoid_: `pkg/simpleredis`, published `github.com/maxlerebourg/simpleredis`

**Redis cache**:
`pkg/cache` `redisCache` when `redisCacheEnabled` is true: one writer plus optional read hosts, each a `*simpleredis.SimpleRedis`.
_Avoid_: local TTL map, mock `serveRedis`

**Effective bouncer instance identity**:
The suffix after the LAPI identity hex in Redis `CachePrefix`: optional Traefik `redisCacheInstanceId` after trim, else `os.Hostname()`, else the literal `unknown-instance` with one Warn. Resolved once per config in `lapi.ResolveCacheInstanceIdentity` during `Prepare`.
_Avoid_: reclaim `SessionKey`, LAPI stream cursor, random per-start id

## Overview

Use the utilities SimpleRedis module for Redis-protocol GET/SET/DEL/MGET. Construct with `simpleredis.New` (dial 2s, command 1s). Hold each client by pointer so the pool mutex is not copied. Do not import the published maxlerebourg module.

**LAPI stream cursor vs Redis:** CrowdSec stores `stream_cursor` on the bouncer database row for this process’s API key hash plus the **outbound IP LAPI sees**. Each pod/replica with a distinct egress IP gets its own row and polls its own stream. Redis in this plugin is a **durable per-bouncer-instance cache** for remediations and the stream poll lease key (`updated`); it is not a shared stream bus and does not replace LAPI’s cursor. Call `lapi.Prepare` before `lapi.New` so instance identity is resolved once.

## How to use

- `Client.New(..., isRedis=true, writeHost, readHosts, pass, database, keyPrefix)` builds the writer and each reader via `simpleredis.New`. `keyPrefix` is `lapi.CachePrefix`: `{SessionHex or IdentityHex}:{instanceId}` when Redis is enabled. Instance id comes from optional Traefik `redisCacheInstanceId` (trimmed); when empty, `os.Hostname()`; on hostname failure the literal `unknown-instance` and one Warn. Set `redisCacheInstanceId` to the Kubernetes pod name (downward API) when hostname is unstable across restarts. Two LAPI Clients on one Redis with the same full prefix share keys (in-process warn-and-wire); different instance ids isolate remediations and the `updated` lease.
- Request lookup uses `GetMany` (Redis `MGET`, one `nextReader()`): the client IP, optional `range-index`, and each present header-scope key. Prefix each logical key. Missing keys are omitted from the result map.
- Cache keys for remediations are the client IP, `scope:value` for header-mapped scopes, and one `range-index` blob, namespaced by `CachePrefix` when Redis is on.
- Commands pass `context.Background()` (the cache API has no request context).
- `SimpleRedis.Close()` drains idle sockets and refuses to pool again. `cache.Client.Close()` closes the writer and every reader. `lapi.Client.Close()` calls that.

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
- `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis/`

## Gotchas

- Do not copy `SimpleRedis` by value after `New`.
- After `Close()`, further Get/Set/Del/MGet return unreachable and do not dial.
- Match miss/unreachable with `IsMiss` / `IsUnreachable` (legacy `redis:*` strings still exist).
- The mock e2e Redis stand-in must speak RESP arrays; inline GET is leftover compatibility.
- Real-stack Redis-cache e2e uses Dragonfly, not Redis.
- Pass a distinct `keyPrefix` per bouncer instance when several pods share one Redis host; memory-only mode keeps the hex base without an instance suffix.
- Do not take utilities zero-Config dial/command defaults (200ms/900ms).
