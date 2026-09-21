# Test coverage

1. [hard] Critical path untested — `pkg/bouncer/bouncer.go:217` — packed memory ban resolves origin via `OriginName` only on drop; tests stop at lookup `originID` (`TestLookupCachedRemediationPackedWord`) and leftover ServeHTTP (`TestServeHTTP_NonCanonicalHeaderHitsCanonicalIpBan` Sets a bare letter)
   → Assert a packed `crowdsec` ban drop records origin `crowdsec`
   Status: done
   Argument: 4d358dce.
2. [hard] Edge case untested — `pkg/lapi/decisionstore.go:138` — intern overflow returns false and `storePackedOrLeftover` Sets leftover; spec scenario "Overflow keeps leftover strings" has no test
   → Assert Intern past uint16 max stores that origin’s Ip slot as a leftover string and GetInt misses
   Status: done
   Argument: 4d358dce.
3. [hard] Edge case untested — `pkg/cache/cache.go:178` — Redis GetInt maps leftover/unparseable to CacheMiss; `Test_GetIntMissesLeftoverString` is memory-only
   → Assert Redis Set leftover then GetInt is cache:miss and Get returns the string
   Status: done
   Argument: 4d358dce.
4. [judgement] Happy path only — `pkg/lapi/client_decisions.go:117` — `rangeIndexRemediation` packed letter+id arm has no stream/blob test; only `TestSplitStoredPackedLine` hits the helper
   → Assert a memory Range apply stores letter plus intern id on `range-index`
   Status: skipped
   Argument: judgement; codec covered by TestSplitStoredPackedLine.
