## 1. Stream store on DecisionStore

- [x] 1.1 Define `streamStore` interface (Put, Delete, BeginTick, PublishTick, LookupRemediation) and wire it on `DecisionStore` at `OpenDecisionStore` (Redis vs memory selection).
- [x] 1.2 Implement `redisStreamStore` delegating Put/Delete/Get path to `cache.Client`; no-op BeginTick/PublishTick.
- [x] 1.3 Implement `memoryStreamStore` with `atomic.Value` `map[string]liveSlot{word, expiresAt}`; tick clone, apply, expiry sweep, single Store.
- [x] 1.4 Remove DecisionStore/Client bolt-on live map fields that duplicate the store (including `LiveSlot.Leftover`).

## 2. Stream apply wiring

- [x] 2.1 Route `storeStreamDecision` / `deleteStreamDecision` for non-Range stream/alone through stream store only (no `liveTick != nil` / cache Set branch on Client).
- [x] 2.2 Wrap each successful `fetchAndApplyStreamDecisions` with BeginTick → apply deleted then new → PublishTick once; keep Range batch and hydrate cadence unchanged.

## 3. Request lookup

- [x] 3.1 Add `Client.LookupStreamRemediation` delegating to stream store + `RangeMembership()` with shared merge in `decisionscope`.
- [x] 3.2 Memory lookup: Load map, one probe per Ip/header key; skip Range when Ip is ban; no GetMany on memory stream path.
- [x] 3.3 Bouncer: stream/alone always call stream lookup; remove `UsesLiveSnapshot` / `LookupLiveSnapshotRemediation` branch.

## 4. Remove bolt-on

- [x] 4.1 Delete `Client.liveTick`, `publishLiveTick`, `UsesLiveSnapshot`, and related test hooks; remove or replace `livesnapshot.go` / live-only lookup paths superseded by store.

## 5. Intern overflow

- [x] 5.1 On memory stream Put: Warn on intern overflow; pack kind-only word (origin id 0); drop leftover string field on slots and tests expecting overflow strings in memory map.

## 6. Tests and benchmarks

- [x] 6.1 Unit tests: tick publish, expiry on publish, delete-before-new, skip-Range-on-Ip-ban, Redis direct Set path, live/none unchanged.
- [x] 6.2 Benchmarks vs `origin/master`: heap retained, allocs/op, sequential/parallel miss; document 100k fixture on delivery card.

## 7. Verify

- [x] 7.1 Run `go test` for `pkg/lapi`, `pkg/decisionscope`, `pkg/bouncer`, and related packages.
