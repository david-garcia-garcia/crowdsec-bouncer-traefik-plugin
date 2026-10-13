# Requirement
IssueKey: 2026-09-18-cache-miss-sentinel

## Problem
On dest `46a81d0`, stream + in-memory cache never stores a negative (`f`) Ip slot. The common allow path is `LookupCachedRemediation` miss then `StreamHealthy` allow. That miss allocates a new `errors.New(CacheMiss)` in `localCache.get` per absent key, another in `LookupCachedRemediation` when the Ip key is absent, then `ServeHTTP` does `cacheErr.Error()` and string-equals `cache.CacheMiss` / `cache.CacheUnreachable`. Ticket-measured: lookup miss 249 ns / 200 B / 9 allocs; full stream allow 524 ns / 408 B / 17 allocs. About half the allow-path allocs are miss-as-error.

## Current (code)
- `CacheMiss` and `CacheUnreachable` are string constants, not sentinel `error` values. `pkg/cache/cache.go`
- `localCache.get` returns `errors.New(CacheMiss)` on absent, invalid, or empty value. `pkg/cache/cache.go`
- `localCache.getMany` omits missing keys; it still calls `get` (and allocates) per key, then string-compares `CacheUnreachable` (local `get` never returns that). `pkg/cache/cache.go`
- `redisCache.get` / `getMany` also `errors.New(CacheMiss)` / `errors.New(CacheUnreachable)` after `simpleredis.IsMiss` / `IsUnreachable`. `pkg/cache/cache.go`
- `LookupCachedRemediation` GetMany-merges Ip, Range membership, and header scopes; if no active remediation and the Ip key is absent it returns `errors.New(cache.CacheMiss)`. `pkg/decisionscope/lookup.go`
- `ServeHTTP` live/stream/alone: on lookup error, `cacheErr.Error()` then string-eq. Unreachable + `!redisUnreachableBlock` passthrough; miss `break`s; other errors ban with cache-fail origin. `pkg/bouncer/bouncer.go`
- After that switch, stream/alone miss (or empty non-`f` value) allows if `StreamHealthy`, else LAPI failure action. Live/none then `LiveLookup`. `pkg/bouncer/bouncer.go`
- Stream apply `storeStreamDecision` Sets only ban/captcha slots; it never Sets `NoBannedValue` (`f`) for clean IPs. Live `cacheLiveScope` / live IP path do store `f`. `pkg/lapi/client_decisions.go` `pkg/lapi/client_live.go`
- Other string-eq call sites: `localCache.acquire`, `readRangeIndex`, `hydrateRangeMembership`. `pkg/cache/acquire.go` `pkg/decisionscope/range.go` `pkg/lapi/client.go`
- Tests assert `err.Error() == CacheMiss` / `CacheUnreachable`. `pkg/cache/zzz_cache_test.go` `pkg/decisionscope/zzz_range_test.go` `pkg/lapi/zzz_decisionstore_test.go`

## Desired
- Package-level sentinel errors on `pkg/cache` (`ErrMiss`; unreachable comparable without `Error()` string eq). Callers use `errors.Is`.
- Stop allocating a new error on every clean stream/in-memory miss.
- Behavior unchanged: stream/alone miss still allow-if-healthy; unreachable still honors `redisUnreachableBlock`; live/none still live-lookup on miss.
- Do not change Redis protocol, stream apply, or store negatives for all IPs.

## Affected
- `pkg/cache/cache.go` (`CacheMiss`, `get`, `getMany`; sentinels)
- `pkg/cache/acquire.go` (string-eq miss/unreachable)
- `pkg/decisionscope/lookup.go`
- `pkg/decisionscope/range.go` (`readRangeIndex`)
- `pkg/bouncer/bouncer.go` (`ServeHTTP` cacheErr branch)
- `pkg/lapi/client.go` (`hydrateRangeMembership`)
- Existing tests that compare `err.Error()` to the string constants

## Out of scope
- Range radix origin walk
- Lazy slog
- Redis pool
- AppSec
- `ttl_map` redesign
- Storing negative (`f`) Ip slots on the stream path
- Redis wire protocol / SimpleRedis miss mapping beyond returning the same sentinels

## Unknowns
- Ticket alloc numbers were not re-measured this prepare.
- Whether `CacheMiss` / `CacheUnreachable` strings stay as `Error()` text of the sentinels (ticket names `ErrMiss` and does not say to delete the strings).
- Whether Redis `get`/`getMany` must return the same sentinels (implied by package-level + `errors.Is`; Redis is not the measured target).

## Tensions
- Ticket names three key files; dest also string-compares miss/unreachable in `acquire`, `readRangeIndex`, and `hydrateRangeMembership`. Those must switch to `errors.Is` or sentinels will not compose.
- `localCache.getMany` already omits misses but still allocates inside `get` per absent key. Sentinel return from `get` removes that alloc without changing GetMany omit-miss behavior.
- Redis miss/unreachable still `errors.New` today. Using the same sentinels is not a protocol change; skipping Redis would leave `errors.Is` broken on Redis modes.
