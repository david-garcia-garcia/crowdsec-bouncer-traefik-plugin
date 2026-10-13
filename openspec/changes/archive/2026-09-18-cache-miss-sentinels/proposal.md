## Why

Stream mode with the in-memory DecisionStore never stores a negative Ip slot. The common allow path is a cache miss, then `StreamHealthy`. Dest allocates a new `errors.New("cache:miss")` in `localCache.get` and again in `LookupCachedRemediation`, then `ServeHTTP` string-compares `Error()`. Every clean request pays that cost.

## What Changes

- `pkg/cache` exports package-level sentinel errors `ErrMiss` and `ErrUnreachable`. Keep `CacheMiss` / `CacheUnreachable` as those sentinels’ `Error()` text.
- `get` / `getMany` (memory and Redis) and `LookupCachedRemediation` return those sentinels. No `errors.New` on a clean miss.
- Callers match with `errors.Is` (`ServeHTTP`, `acquire`, `readRangeIndex`, `hydrateRangeMembership`, tests). Behavior unchanged: stream/alone miss still allow-if-healthy; unreachable still honors `redisUnreachableBlock`; live/none still live-lookup on miss.
- GetMany still omits missing keys.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_cache_client_decision-store`: store errors are package sentinels (`ErrMiss`, `ErrUnreachable`); callers SHALL use `errors.Is`. `Error()` text stays `cache:miss` / `cache:unreachable`.

## Impact

- `pkg/cache/cache.go`, `pkg/cache/acquire.go`
- `pkg/decisionscope/lookup.go`, `pkg/decisionscope/range.go`
- `pkg/bouncer/bouncer.go` (`ServeHTTP` cacheErr branch)
- `pkg/lapi/client.go` (`hydrateRangeMembership`)
- Tests that compare `err.Error()` to the string constants
- Usage gotcha on `knowledge/devdocs/core_cache_client.md` after apply
- No **BREAKING** public JSON/YAML keys
- Out of scope: Range radix origin walk, lazy slog, Redis pool, AppSec, `ttl_map` redesign, storing stream negatives, Redis wire protocol
