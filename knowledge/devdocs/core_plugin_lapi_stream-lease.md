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

## Pattern snippet

```go
won, err := c.Cache().Acquire(context.Background(), cacheTimeoutKey, decisionscope.NoBannedValue, leaseDuration)
if !won {
	c.hydrateRangeMembership()
	return nil
}
```

## Key files

- `pkg/lapi/client_stream.go`
- `pkg/cache/acquire.go`

## Gotchas

- Do not use `atomic.Pointer[T]` to hold the lease.
- Do not turn write-once Client scalars into mutable lease fields.
- `cache.Client.Acquire` is the cache API (`core_cache_redis.md`). Isolation of the `updated` key is the DecisionStore (`core_cache_client.md`).
