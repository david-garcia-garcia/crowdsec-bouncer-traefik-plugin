# Test coverage

1. [hard] Assertion does not prove the job — `pkg/lapi/client_live.go:59` — LiveLookup returns `(kind, origin, error)`; `TestLiveLookup_ScopeBanWins` keeps origin as `_` and only checks `IsActiveRemediation(value)`, so concat-then-split would stay green
   → Assert LiveLookup on a Country ban returns kind ban and that decision’s origin name
   Status: done
   Argument: f92c8573 TestLiveLookup_ScopeBanWins asserts kind ban and origin CAPI.
2. [hard] Edge case untested — `pkg/decisionstore/memory.go:123` — intern overflow Warn; `TestStoreInternOverflowUsesGenericOrigin` asserts origin id 0 only (ERROR logger, no Warn)
   → After FillUntilMaxForTest, Put an overflow origin and assert a Warn with stem `decisionstore:intern overflow`
   Status: done
   Argument: f92c8573 added TestMemoryInternOverflowWarns.
3. [hard] Critical path untested — `pkg/decisionstore/redis.go:92` — replica Get miss must not retry the writer; `TestApplyRangeBatch_UnreachableReadKeepsSharedIndex` covers unreachable only; `(none)` for miss
   → With a populated writer and an empty replica, Lookup/Get is `store:miss` and the writer is not read
   Status: done
   Argument: f92c8573 added TestRedisReplicaMissDoesNotReadWriter.
4. [hard] Edge case untested — `pkg/decisionstore/memory.go:81` — tick Put mutates tick only; `TestMemoryTickPublishLookup` / `checkStreamTickPutVisibleAfterPublish` assert the hit after PublishTick (`zzz_backend_test.go:73` says isolation is out of the matrix)
   → Lookup after BeginTick+Put and before PublishTick must miss (or keep the prior published generation)
   Status: done
   Argument: f92c8573 added TestMemoryTickPutHiddenUntilPublish.
5. [hard] Edge case untested — `pkg/decisionstore/memory.go:141` — tick Delete; tests only Delete with no tick (`checkLivePutIPBanThenDelete`); `TestHunt_StreamAppliesDeletedBeforeNew` still passes if Delete is a no-op
   → Stream delete-only (or BeginTick+Delete+PublishTick) leaves that Ip a miss
   Status: done
   Argument: f92c8573 added TestMemoryTickDeleteOnlyMissesAfterPublish.
6. [judgement] Happy path only — `pkg/bouncer/bouncer.go:239` — none mode skips Store memo and always LiveLookup; ServeHTTP tests are stream hits only
   → Assert none mode with a Store ban still calls LiveLookup (does not remediate from the memo), or skip if unreachable
   Status: skipped
   Argument: judgement; unattended apply is hard findings only.
