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
- Request lookup uses `GetMany` (Redis `MGET`, one reader): the client IP, optional `range-index`, and each present header-scope key. Prefix each logical key. Missing keys are omitted from the result map.
- Reads pick their host through `readerFor`, not `nextReader` directly. A key this client just wrote (`set`, `delete`, or `acquire`) reads from the **writer** for `writerPinWindow`; everything else keeps the round-robin over the read hosts. That is read-your-writes for the request path without taking the per-request lookup load off the replicas.
- Use `Client.GetConsistent` when a read must not be stale at all: a read-modify-write of a shared blob, or a read whose result is memoised and served for longer than the pin window. Both Range-index reads use it (`readRangeIndex`, `hydrateRangeMembership`). Do not use it for `LookupCachedRemediation`.
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
- The pin window bounds the stale-read window; it does not abolish it. A read host lagging longer than `writerPinWindow` still answers stale outside the window, and that is a deployment to fix, not a constant to widen. It is deliberately not a configuration key.
- Do not turn the pin into one deadline covering every key. In `live` mode the cache is a per-request memo, so writes never stop and such a deadline would never lapse: every read would land on the writer, which is the regression the per-key pin exists to avoid.
- A write burst past `writerPinMaxKeys` (a `startup=true` stream pull is one) pins **all** reads for the window instead of growing the set. Overflow fails toward the writer, never back to a replica.
- When read hosts are set, unpinned Get and GetMany call `nextReader` only; a miss or replica error is not retried on the writer. Empty readers return the writer. Pinned keys use the writer via `readerFor`.
- `Client.Set` and `Delete` are void: Redis write errors are logged and discarded. Do not add an error return. Stream and live must not fail closed on a write miss.
- When a write proceeds, Redis Set sends `SET EX` with the duration as given. Do not omit `EX` or clamp. `Client.Set` no-ops a non-positive duration (see `core_cache_client.md`); stream still passes `int64(duration.Seconds())` with no clamp.
