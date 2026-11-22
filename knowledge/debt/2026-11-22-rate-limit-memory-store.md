# Add the in-memory rate-limit store (`rateLimitStore: memory`)

IssueKey: 2026-11-20-add-redis-rate-limit-leg
Size: large
Action: note

## Why this follow-up

The requested rate-limit design has two stores (`redis`, `memory`). The rate-limit leg ships only `redis`; `rateLimitStore: memory` fails startup as not supported in this version. Single-replica operators without Redis cannot use the rate limiter.

## Why it was not taken

Not asked in round 2 addendum C, which took the other half of the round-1 note (`knowledge/debt/2026-11-20-rate-limit-token-bucket-and-memory-store.md`): the limiter-level `rateLimitAlgorithm` with `tokenBucket`. The conductor's proposal lists the memory store as out of scope ("not asked; per-replica").

## Risks

A memory store counts per Traefik replica, so N replicas admit up to N times each limit; the README would have to say so. `windowcounter` has no in-memory variant in utilities `v1.0.12`, so a memory store would serve only `tokenBucket` unless the sliding window gains one.

## Context

Current: `pkg/configuration/configuration.go` (`validateRateLimit` accepts only `RateLimitStoreRedis`), `pkg/ratelimit/client.go` (`Open` always builds a `simpleredis` client).
Proposed: `tokenbucket.Memory` (utilities `v1.0.12`, same `Status` and clock as `tokenbucket.Redis`, fixed by PR #54 in `v1.0.9`) behind the existing `Counter` contract as a third adapter; decide what `slidingWindow` does with `memory` (reject, or a new in-memory window counter upstream).
