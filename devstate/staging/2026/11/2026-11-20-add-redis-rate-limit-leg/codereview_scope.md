# Scope

1. [hard] Scope vs Requirements — `pkg/ratelimit/bucket_set.go:107` — Desired config shape asks for `algorithm: tokenBucket` with `burst` and `rateLimitStore: memory`; the diff rejects all three at startup (`bucket_set.go:107`, `:112`, `pkg/configuration/configuration.go:487`) and ships only the Redis sliding window
   Fix: Implement tokenBucket (with burst) and the memory store, or record the cut as an approved reshape in `deviations.md` / `## Out of scope` (only the in-memory sliding window is out of scope today)
   Status: skipped
   Argument: demand gap; not applied unattended. The cut is recorded in `knowledge/debt/2026-11-20-rate-limit-token-bucket-and-memory-store.md` (upstream over-admit bug) and the three values fail at startup instead of being ignored.
   Note:
   ```
   Deferred in knowledge/debt/2026-11-20-rate-limit-token-bucket-and-memory-store.md
   (upstream tokenbucket over-admit, utilities PR #54 untagged). A debt note is not an approved deviation.
   ```
2. [judgement] Scope vs Requirements — `pkg/bouncer/bouncer_serve_ratelimit.go:54` — Desired `rateLimitResponseHeaders: true # Retry-After (+ RateLimit-* headers)`; the diff sends `Retry-After` only, no `RateLimit-*` headers
   Fix: Add the `RateLimit-*` headers, or record the Retry-After-only cut as an approved reshape in `deviations.md`
   Status: skipped
   Argument: judgement: deferred in `knowledge/debt/2026-11-20-rate-limit-ratelimit-response-headers.md`; README limits state that no `RateLimit-*` headers are sent.
   Note:
   ```
   Deferred in knowledge/debt/2026-11-20-rate-limit-ratelimit-response-headers.md (IETF draft naming unsettled).
   README.md:918 documents the limit.
   ```
