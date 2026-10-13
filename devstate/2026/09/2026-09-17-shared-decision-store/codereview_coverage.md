# Test coverage

1. [hard] Assertion does not prove the job — `pkg/lapi/decisionstore.go:81` — `OpenDecisionStore` prefixes Redis with `SessionHex`; `TestCachePrefix_LiveIsSessionHexNotIdentityHex` (`pkg/lapi/zzz_decisionstore_test.go:80`) only asserts unused `CachePrefix()`; reverting the `New` prefix to `IdentityHex` stays green
   → Assert a live `OpenDecisionStore` Redis GET/SET/Eval key uses `SessionHex`, not `IdentityHex` (same host, two prefixes: first Set is a miss on the second)
   Status: done
   Argument: TestOpenDecisionStore_LiveRedisPrefixIsSessionHexNotIdentityHex Sets then Gets via SessionHex vs IdentityHex clients.
2. [hard] Critical path untested — `pkg/lapi/decisionstore.go:84` — store reclaim Close hook is `cache.Client.Close()`; test: `(none)` that last constructor ctx cancel + grace runs Close and a later Redis Get is unreachable
   → Assert last-holder grace Close drains the Redis pool
   Status: done
   Argument: TestOpenDecisionStore_LastHolderGraceClosesRedisPool cancels last holder and asserts CacheUnreachable.
