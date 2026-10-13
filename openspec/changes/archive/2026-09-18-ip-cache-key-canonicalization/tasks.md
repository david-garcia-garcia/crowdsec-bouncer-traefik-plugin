## 1. Ip cache key canonicalization (both sides, one commit)

- [x] 1.1 `IPCacheKey` collapses any value that parses as a bare address to `net.IP.String()`
- [x] 1.2 Add `IPLookupCacheKey(remoteIP, ipAddr)` and use it in `LookupCachedRemediation` / `LookupCacheKeys`
- [x] 1.3 `handleNoStreamCache` writes the live memo under `IPCacheKey(remoteIP)`, not the raw header text
- [x] 1.4 Failing-first: store/lookup spelling pairs in both directions (`TestStoreStreamDecision_SpellingsShareOneCacheSlot`)
- [x] 1.5 Failing-first: live-mode caching measurement that catches read-side-only canonicalization (`TestLiveLookup_MemoHitsOnRepeatedRequests`)
- [x] 1.6 Invariant: the store key and the lookup key agree for every spelling (`TestIPLookupCacheKeyAgreesWithStore`)
- [x] 1.7 Guard: a Country value is not pushed through IP parsing

## 2. Range-index apply guard

- [x] 2.1 `readRangeIndex` returns `(string, error)`; `CacheMiss` stays an empty index
- [x] 2.2 `ApplyRangeBatch` returns the error and writes nothing
- [x] 2.3 `fetchAndApplyStreamDecisions` returns it so the poll is reported as failed
- [x] 2.4 Failing-first: dead read replica plus healthy writer; assert the stored blob survives upsert and removal
- [x] 2.5 Failing-first: the failed poll releases the lease and stays in startup
- [x] 2.6 `testLeaseRedis` learns `DEL` so the lease assertion is real

## 3. Verify

- [x] 3.1 `go build ./...`, `go vet ./...`
- [x] 3.2 `go test ./pkg/... -count=1`, `go test . -count=1` (yaegi)
- [x] 3.3 `golangci-lint run ./...`
- [x] 3.4 `-race` in Docker, with the pre-existing `pkg/lapi` test race measured on DestBranch too
- [x] 3.5 Spec leaf and `knowledge/devdocs/core_plugin_decisionscope.md` in sync
