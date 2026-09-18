# Sentinel cache miss on the stream allow path

Problem: Stream mode with the in-memory DecisionStore never stores negative (f) Ip slots. The common high-traffic path is LookupCachedRemediation miss → StreamHealthy → allow. Today that miss allocates: localCache.get does errors.New(CacheMiss) per missing key; LookupCachedRemediation does errors.New(CacheMiss) again when the Ip key is absent; ServeHTTP then cacheErr.Error() and string-compares to cache.CacheMiss / CacheUnreachable. Measured: lookup miss alone is 249 ns / 200 B / 9 allocs; full stream allow is 524 ns / 408 B / 17 allocs. About half the allow-path allocs are this miss-as-error.

Desired: Package-level sentinel errors on pkg/cache (ErrMiss, and keep unreachable comparable without Error() string eq). Callers use errors.Is. Stop allocating a new error on every clean request. Behavior unchanged: miss in stream/alone still means allow-if-healthy; unreachable still honors redisUnreachableBlock; live/none still live-lookup on miss. Do not change Redis protocol, stream apply, or store negatives for all IPs.

Out of scope: Range radix origin walk, lazy slog, Redis pool, AppSec, ttl_map redesign.

Key files: pkg/cache/cache.go (CacheMiss, get, getMany), pkg/decisionscope/lookup.go, pkg/bouncer/bouncer.go ServeHTTP cacheErr branch, existing cache/decisionscope/bouncer tests.

Deployment constraint: stream mode + in-memory cache. Redis must keep working for other modes but is not the target.
