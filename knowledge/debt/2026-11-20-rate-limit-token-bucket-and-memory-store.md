# Add the `tokenBucket` algorithm and the in-memory rate-limit store

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up

The requested rate-limit design has two algorithms (`slidingWindow`, `tokenBucket` with `burst`) and two stores (`redis`, `memory`). The first slice ships only `slidingWindow` on Redis.

## Why it was not taken

Upstream blocker. `tokenbucket` at the pinned utilities `v1.0.7` admits refunded consumes: refund is decided in whole microseconds and admit in truncated nanoseconds. Measured on a rate-limiter shape (maxDelay 0, hot key under flood): rate 1000/s admitted 3029 where the correct bucket admits 1999. The returned `wait` is the truncated value, so the plugin cannot correct it on the published surface. The fix is upstream PR #54, tagged in utilities `v1.0.9` (pinned since 2026-11-21); the algorithm and store are still not built. The only in-memory limiter in the module is `tokenbucket.Memory`, so the memory store carries the same defect. Finding: `knowledge/research/ext_traefik-middleware-utilities_tokenbucket/`.

## Risks

Single-replica operators without Redis cannot use the rate limiter until this lands. Building on `tokenbucket` before #54 is tagged ships a limiter that over-admits under exactly the flood it exists to stop.

## Context

Workaround this change ships: no `tokenBucket`, no `memory` store, no `burst` key. Unblock: merge utilities PR #54, tag it, bump `go.mod`, vendor `tokenbucket`, then add the algorithm and store (one `tokenbucket` limiter per bucket, since rate and burst are fixed at `New`).
