# 2026-09-18-cache-accepted-semantics

host: local
ref: none

## Caller spec (document only)

Do not change Redis/memory behavior, signatures, or tests that assert new runtime policy.

Closed #38 wanted: (1) Get recently written keys from the Redis writer (read-your-writes), (2) duration<=0 no-op aligned on memory and Redis, (3) Set/Delete return error for fail-closed stream/captcha.

Owner decided:

1. Read-your-writes is rejected as overengineering. Forget it. nextReader stays replica round-robin when LapiRedisReadHosts is set; when empty, reads are the writer. Replica lag after a primary Set (stream miss → allow) is accepted. Do not retry Get on the writer on miss. Do not keep a local set of written keys.
2. TTL <= 0 / Redis SET EX 0 is accepted. storeStreamDecision uses int64(duration.Seconds()); sub-second CrowdSec durations become 0; SimpleRedis always sends SET EX <n>; Redis rejects EX 0; key is not stored; error is logged. liveCacheTTL already substitutes bouncerLiveTtlSeconds when durationSecond<=0 — do not change that. Do not clamp stream TTL. Do not make localCache match Redis.
3. Set/Delete stay void. redisCache.set/delete log and return. Callers do not fail-close on write miss. Captcha grace is the HMAC cookie, not cache.

Persist so a future defect hunt does not re-open these:

- Fold into existing cache specs (likely core_cache_redis_utilities-client and/or core_cache_client_isolated-store / DecisionStore packet). Add SHALL/MUST NOT requirements + scenarios that describe CURRENT behavior as the contract (replica reads, void Set, EX as given). Use sbs-dev-speclibrarian / FindSpecHost when picking spec ids (propose will do that; prepare just notes likely hosts).
- Short comments at the actual code (pkg/cache/cache.go nextReader/get/set, and stream int64(duration.Seconds()) if a one-liner earns its keep) that point at the accepted tradeoff — not essays.
- knowledge/devdocs gotchas on the existing cache packet if devdocsimpact says so.
- README LapiRedisReadHosts already mentions replica outage; only add a lag/stale-read sentence if explore finds the knob text still implies reads are consistent with the last write.

Bound: no Set error return, no writer-on-recent-key, no EX clamp, no captcha cache grace, no SimpleRedis fork. Do not implement backendbackoff, timeouts, captcha JSON, or module rename.

Do NOT reuse closed PR #38 or branch 2026-09-06-cache-redis-semantics.
