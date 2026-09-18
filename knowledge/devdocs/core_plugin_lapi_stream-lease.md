# Stream lease

## Language

**Stream lease**:
The `updated` cache key that grants one winner the right to call CrowdSec `GET /v1/decisions/stream`.
_Avoid_: Get-then-Set, `atomic.Pointer[T]`, SetNX

## Overview

Acquire `updated` in one DecisionStore operation before a stream poll. Redis uses one Eval. Memory takes a mutex around miss+Set. The loser hydrates Range membership from the shared store and must not GET stream.

## How to use

- Call `cache.Client.Acquire(ctx, "updated", value, duration)` from `handleStreamCache`. Pass `context.Background()` (the cache API has no request context).
- Floor TTL is 1s (`updateInterval - 1`, min 1). The caller owns the floor.
- Redis: one `Eval` (`EVALSHA` then `EVAL` on NOSCRIPT) on the writer plus the store’s `SessionHex` prefix.
- Memory: mutex around miss+Set (vendored `ttl_map` Get and Set are separately locked).
- Do not Get-then-Set. Do not add a SetNX wrapper. Do not put poller or LAPI query logic on `cache.Client`.
- Two concurrent acquirers on one store: exactly one winner may GET `/v1/decisions/stream`.
- Release the lease when the poll you won then fails: `c.Cache().Delete(cacheTimeoutKey)` before returning the error. Keep the fetch+apply body in one function (`fetchAndApplyStreamDecisions`) so GET, decode, and apply all release through the same line. Apply order (deleted before new) is `core_plugin_lapi_stream-apply.md`.
- A poll that succeeds keeps the key. Do not delete on the success arm — later ticks inside the interval must still skip LAPI.

## Pattern snippet

```go
won, err := c.Cache().Acquire(context.Background(), cacheTimeoutKey, decisionscope.NoBannedValue, leaseDuration)
if !won {
	c.hydrateRangeMembership()
	return nil
}
if pollErr := c.fetchAndApplyStreamDecisions(); pollErr != nil {
	c.Cache().Delete(cacheTimeoutKey)
	return pollErr
}
```

## Key files

- `pkg/lapi/client_stream.go`
- `pkg/cache/acquire.go`

## Gotchas

- Do not use `atomic.Pointer[T]` to hold the lease.
- Do not turn write-once Client scalars into mutable lease fields.
- `cache.Client.Acquire` is the cache API (`core_cache_redis.md`). Isolation of the `updated` key is the DecisionStore (`core_cache_client.md`).
- The lease is not the intra-instance poll lock. Overlapping `handleStreamTicker` on one Client is `core_plugin_lapi_stream-single-flight.md`.
- Do not release on the loser branch. The loser never owned the key, and deleting it there hands every tick a free GET.
- Release is one store-agnostic `cache.Client.Delete`. Redis and memory behave the same; do not add a poller-side branch on the store kind.
- A failed poll releases the lease but does not clear the startup flag. `isCrowdsecStreamStartup` drops to `0` only on a poll that finished.
