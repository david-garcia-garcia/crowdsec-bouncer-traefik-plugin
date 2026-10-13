# Standards

1. [hard] Name for the scope — `pkg/lapi/zzz_decisionstore_test.go:44` — `a` and `b` are placeholders for the two Redis-host configs (`a`/`b` again at `:61` and as base vs header-map at `:129`)
   → Rename the Redis-host pair to `redisA`/`redisB` and the header-mismatch pair to `base`/`withHeaders`
   Status: done
   Argument: renamed redis-host pair to redisA/redisB and header-mismatch pair to base/withHeaders.
2. [hard] Leave a trail — `pkg/lapi/decisionstore.go:24` — `storeParamsFrom` has no job comment; siblings `sessionFrom` and `settingsFrom` say they copy fields and must run after Prepare (Redis password is resolved there)
   → Add one comment: copies Redis store fields off cfg; call after Prepare
   Status: done
   Argument: added job comment on storeParamsFrom (call after Prepare).
3. [hard] Symmetry and consistency — `pkg/lapi/client_stream.go:128` — `handleStreamCache` acquires and hydrates via `c.Cache()` but still writes the range batch through `c.cacheClient`
   → Pass `c.Cache()` to `ApplyRangeBatch`
   Status: done
   Argument: ApplyRangeBatch now takes c.Cache().
