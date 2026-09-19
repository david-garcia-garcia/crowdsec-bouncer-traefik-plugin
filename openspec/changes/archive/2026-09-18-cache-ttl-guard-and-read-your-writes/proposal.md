## Why

On DestBranch `pkg/cache` has no guard for a non-positive write lifetime, and the two backends do
not agree about what one means. Measured on `fad36a1`: the in-memory TTL map stores a negative TTL
as `Timestamp = -1`, which its own `Get` reads as **never expires**, so a cached ban outlives the
decision that justified it with no upper bound; a zero TTL is dropped without touching an entry that
is already there. Redis rejects the same write with `ERR invalid expire time in 'set' command`, so
nothing is stored and every call logs an error. The lease verb has the same hole: a negative lease
in memory never expires, which stops that instance polling the stream for good, and a zero one
stores nothing, so every caller wins and the lease excludes nobody.

Separately, every cache read goes round-robin through `redisCache.nextReader()`. With
`RedisCacheReadHosts` on a lagging replica, an IP the stream poller has just banned reads back as a
miss, and stream and alone mode read a miss as "no decision affecting this IP"
(`bouncer.go:202-222`), so the plugin serves the request it had already decided to block. The same
lag corrupts the shared Range index: `ApplyRangeBatch` is a read-modify-write, so a stale read
rebuilds the blob from an old base and writes the truncated result back for every instance.

## What Changes

- Guard a non-positive duration at the `cache.Client` boundary. `Set` returns without touching the
  backend. `Acquire` takes no lease and returns `cache:bad-ttl`. `Delete` carries no duration and is
  unchanged.
- Pin a key to the Redis writer for a bounded window after `set`, `delete`, or `acquire` writes it.
  `get` and `getMany` use the writer while any requested key is inside its window and otherwise keep
  the round-robin over the read hosts. The window is a constant in `pkg/cache`, not a config knob.
- Cap the pinned-key set. Overflow pins every read for the window rather than dropping keys, so it
  fails toward the writer and never silently back to a stale replica.
- Add `Client.GetConsistent`, which always reads the authoritative copy, and use it for the two
  Range-index reads: `readRangeIndex` (a read-modify-write) and `hydrateRangeMembership` (a read
  whose result is memoised as `lastRangeIndex` and served on every request until the blob changes).

## Capabilities

### New Capabilities

- `core_cache_client_write-lifetime`: what a non-positive write lifetime means at the `cache.Client`
  boundary, on both backends and on both the value and the lease verb.

### Modified Capabilities

- `core_cache_redis_utilities-client`: read routing over the writer and the read hosts — the pin
  window after a write, its bounded overflow, and the consistent-read entry point.

## Impact

- `pkg/cache/cache.go`, `pkg/cache/acquire.go`
- `pkg/decisionscope/range.go` (one read swapped to `GetConsistent`)
- `pkg/lapi/client.go` (one read swapped to `GetConsistent`)
- `pkg/cache/zzz_fakeredis_test.go`, `pkg/cache/zzz_ttl_guard_test.go`,
  `pkg/cache/zzz_writer_pin_test.go`, `pkg/decisionscope/zzz_stale_read_test.go` (new)
- Usage `knowledge/devdocs/core_cache_client.md` and `knowledge/devdocs/core_cache_redis.md`
- No new configuration key, header, or Redis key shape. No **BREAKING** public JSON/YAML keys.
- Out of scope: propagating `error` through the cache API (#38's third part, dropped in triage);
  cache key construction (PR #77 owns it); the stream lease design, which already runs against the
  writer; any change inside the vendored `simpleredis`.
