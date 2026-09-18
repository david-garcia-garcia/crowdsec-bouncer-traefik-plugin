## 1. Cache sentinels

- [ ] 1.1 Add `ErrMiss` and `ErrUnreachable` on `pkg/cache` wrapping `CacheMiss` / `CacheUnreachable`
- [ ] 1.2 Return those vars from `localCache.get`, Redis `get` / `getMany`, and acquire unreachable paths
- [ ] 1.3 Switch cache tests from `err.Error() == CacheMiss` to `errors.Is`; keep one `Error()` text assert

## 2. Callers

- [ ] 2.1 `LookupCachedRemediation` returns `cache.ErrMiss`
- [ ] 2.2 `ServeHTTP` cacheErr branch uses `errors.Is` for miss and unreachable
- [ ] 2.3 `localCache.acquire`, `readRangeIndex`, and `hydrateRangeMembership` use `errors.Is`
- [ ] 2.4 Update decisionscope / lapi / bouncer tests that compare `err.Error()` to the string constants

## 3. Usage

- [ ] 3.1 Add the `errors.Is(..., cache.ErrMiss)` gotcha on `knowledge/devdocs/core_cache_client.md`
