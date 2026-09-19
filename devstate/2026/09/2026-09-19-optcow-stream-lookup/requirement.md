# Requirement
IssueKey: 2026-09-19-optcow-stream-lookup

## Problem
Stream IP/header decisions are still modeled as “whatever `cache.Client` is” (Redis pool or TTL map). OptCOW then bolted a third store onto `lapi.Client` (`liveTick` vs `cache.Set`, `UsesLiveSnapshot` vs `LookupCachedRemediation`). That is the wrong domain split: `Client` should apply stream New/Deleted and look up a request without knowing the backend. Two store implementations: Redis uses `cache.Client`; memory uses the copy-on-write `LiveSlot` map. Bolt-on branching on this PR is the defect to remove.

DestBranch is `master` (not frozen `main`).

## Current (code)
- `DecisionStore` owns one `cache.Client` and an `atomic.Value` live snapshot; `PacksMemory()` is `!redisBacked`.
- `Client.liveTick` is a tick scratch map. `storeStreamDecision` / `deleteStreamDecision` branch `if c.liveTick != nil` vs `cacheClient.Set`/`Delete`.
- `fetchAndApplyStreamDecisions` sets `liveTick` when `UsesLiveSnapshot()`.
- ServeHTTP branches stream/alone + `UsesLiveSnapshot()` → `LookupLiveSnapshotRemediation`, else `LookupCachedRemediation`.
- Lease and range-index still use `cache.Client` on both backends.
- Live/none still `Set` leftover strings on `cache.Client`.
- `LiveSlot` still has a leftover-string field for intern overflow.

## Desired
- Lift stream IP/header put, delete, tick publish, and request lookup onto a store abstraction with two implementations (names from explore; meaning is Redis vs memory).
- Redis implementation: existing `cache.Client` for those slots. No COW map.
- Memory implementation: one `atomic.Value` `map[string]liveSlot{word uint32, expiresAt int64}`. Tick: clone, apply, drop expired, Store once. Lookup: Load, one probe per key, skip Range when IP is ban. Do not `Set` those keys on the TTL heap.
- `lapi.Client` must not carry `liveTick` or `if liveTick != nil` / `UsesLiveSnapshot` lookup switches. Stream apply always talks to the store.
- `cache.Client` stays a utility: stream lease, range-index blob, live/none memo (unchanged this ticket).
- Intern overflow is not a production leftover path: log Warn; do not keep a leftover string field on the memory slot to serve GetMany.
- Range Contains on immutable hydrate snapshots must not exclusive-Lock.
- Delivery card: measured heap, allocs/op, sequential+parallel miss vs `origin/master`, with why.
- PR target `master`.

## Affected
- `pkg/lapi/` DecisionStore / Client stream apply / lookup wiring
- `pkg/decisionscope/` lookup entry used by the store
- `pkg/bouncer/bouncer.go` ServeHTTP (call store lookup; no snapshot-vs-cache branch)
- Tests that seed `liveTick` or assert TTL copies
- OpenSpec change for this IssueKey (replace bolt-on deltas)

## Out of scope
- Path-compressed Patricia combining IPs and ranges
- Packing live/none onto the memory map (still `cache.Client` strings)
- Removing `GetMany` from Redis/live leftover lookup
- Stuffing IPs into Helper as /32s
- Changing GitHub `origin/HEAD` (operators set dest `master`)

## Unknowns
- Exact type/package names for the two implementations (DecisionStore methods vs a small interface).
- Whether Redis `BeginTick`/`PublishTick` are no-ops on the same interface or Redis has no tick API.

## Tensions
- Memory still needs `cache.Client` for lease and range-index — the store split is IP/header lookup, not “memory has no cache.”
- Live/none still uses `LookupCachedRemediation`; stream/alone must not reintroduce a Client-level snapshot flag to hide that.
- Existing implement on this branch is the bolt-on to replace, not to extend.
