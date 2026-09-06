## Context

See proposal.md — Why. Memory skips TTL-zero writes; Redis sent `EX 0`. Redis Set/Delete logged and swallowed errors. Gets used round-robin readers only. CRUD tests hit `localCache` exclusively.

## Goals / Non-Goals

**Goals:**
- One TTL-zero contract on both backends.
- Observable write failures from `Set`/`Delete`.
- Read-your-writes for keys this instance wrote on Redis.
- Redis CRUD parity tests in CI.

**Non-Goals:**
- Fail-closed stream lease / captcha on write error (follow-up).
- Sub-second LAPI duration truncation.
- `simpleredis` replication or negative TTL coercion.
- Remediation encoding, key prefix design, localCache mutex.

## Decisions

1. **`duration <= 0` no-op.** Skip store on memory and Redis; return `nil`. Matches existing memory test at `cache_test.go:66`.
2. **Error return on Set/Delete.** Redis propagates; memory returns `nil`. Still log Redis failures.
3. **Read-your-writes via `sync.Map`.** Track keys successfully Set on this `redisCache`; route `Get`/`GetMany` to writer when any requested key is tracked; clear on `Delete`. No TTL on the map.
4. **Fake Redis in `pkg/cache` tests.** Local test helper with separate writer/reader stores for lag simulation.

## Risks / Trade-offs

- [Memory of written keys grows until Delete] → bounded by active decisions per instance; same as cache key cardinality.
- [Call sites ignore errors] → documented follow-up; API enables captcha hardening ticket.

## Migration Plan

Plugin version bump. No config changes. Callers must handle new error return (compile-time).

## Open Questions

None. Policies on `devstate/explore.md`.
