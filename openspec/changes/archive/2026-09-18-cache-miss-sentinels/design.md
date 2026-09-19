## Context

See `proposal.md` Why. Dest `pkg/cache` exports `CacheMiss` / `CacheUnreachable` as strings. `localCache.get`, Redis `get`/`getMany`, and `LookupCachedRemediation` each `errors.New` those strings. `ServeHTTP`, `acquire`, `readRangeIndex`, and `hydrateRangeMembership` string-compare `Error()`. Vendored SimpleRedis already has `ErrMiss` / `ErrUnreachable` plus `IsMiss` / `IsUnreachable`; dest maps those into a new `errors.New`.

FindSpecHost:

```
verdicts:
  - { deltaId: cache-miss-sentinels, fold: fold, spec-id: core_cache_client_decision-store, confidence: high, candidates: [core_cache_client_decision-store, core_cache_client_isolated-store, core_cache_redis_utilities-client, core_plugin_decisions_scopes, core_plugin_middleware_bouncer] }
```

Search: `core_cache_client_decision-store` is the only owner that SHALL-names store errors (`CacheMiss` / `CacheUnreachable`). Isolated-store is key-space isolation. Redis utilities-client is SimpleRedis wiring. Decisions scopes and bouncer consume the error; they do not own it.

## Goals / Non-Goals

**Goals:**

- One `ErrMiss` and one `ErrUnreachable` on `pkg/cache`.
- Clean in-memory miss and lookup miss return those vars (no per-request `errors.New`).
- All dest string-eq sites use `errors.Is`.
- Existing `Error()` text stays so a leftover `err.Error() == CacheMiss` still matches during the switch.

**Non-Goals:**

- Storing `f` for every clean stream IP.
- Changing Redis RESP / SimpleRedis protocol.
- Lazy slog on `Get` / `GetMany`.
- New spec family or a second leaf for bouncer/lookup match.

## Decisions

1. **Package vars `ErrMiss` / `ErrUnreachable` wrapping the existing string constants.** Alternative: only `ErrMiss` and keep unreachable as a string — rejected (ticket requires unreachable comparable without `Error()`). Alternative: delete the string constants — rejected (explore assumed keep `Error()` text).
2. **Return the vars from memory get, Redis get/getMany, acquire unreachable paths, and `LookupCachedRemediation`.** Alternative: wrap with `fmt.Errorf("%w", ErrMiss)` — rejected (re-allocates; `errors.Is` would work but the ticket is the alloc).
3. **Redis maps `simpleredis.IsMiss` / `IsUnreachable` to the same package sentinels.** Alternative: return SimpleRedis errors — rejected (`errors.Is(..., cache.ErrMiss)` would fail).
4. **Fold onto `core_cache_client_decision-store`.** Do not add restated SHALL on bouncer or decisionscope.
5. **Tests switch to `errors.Is`.** Keep asserting `Error()` text on at least one cache miss/unreachable case so the string contract stays proven.

## Risks / Trade-offs

- [A caller still string-compares after a wrap] → This change does not wrap; `errors.Is` at every dest site. New callers follow usage gotcha.
- [Yaegi / plugin load and package-level `error` vars] → Same pattern as `pkg/appsec` `ErrFailureCaptcha` and vendored SimpleRedis; no new global table.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert.
