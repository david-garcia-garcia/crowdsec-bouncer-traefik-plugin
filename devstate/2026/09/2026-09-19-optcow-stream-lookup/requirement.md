# Requirement
IssueKey: 2026-09-19-optcow-stream-lookup

## Problem
Stream/alone in-memory request lookup still walks the TTL heap per key (GetInt/GetMany), may batch leftover string keys, and consults Range membership through iplookup.Helper.Contains under an exclusive mutex. Stream ticks mutate the same TTL store the request path reads, so IPs can exist twice (packed words in ttl_map plus no separate snapshot). Ticket asks for one immutable snapshot per tick (map[string]uint32 plus Range membership) published via atomic.Value, lock-free Load on ServeHTTP, expired IP slots dropped on publish—not on Get—and benchmark proof vs origin/main.

## Current (code)
- `pkg/lapi/decisionstore.go`: memory DecisionStore uses `cache.Client` backed by `ttl_map.Heap` when Redis is off (`pkg/cache/cache.go` localCache).
- `pkg/lapi/client_stream.go`: `fetchAndApplyStreamDecisions` writes each non-range decision via `storeStreamDecision` into that TTL map; `handleStreamCache` calls `hydrateRangeMembership` each tick (`pkg/lapi/client.go`).
- `pkg/lapi/client.go`: `rangeMembership` and `lastRangeIndex` are already `atomic.Value`; `storeRangeMembership` stores `*decisionscope.RangeMembership` built from range-index blob.
- `pkg/lapi/client_decisions.go`: `storeStreamDecision` calls `cacheClient.Set` with `decisionscope.Pack` uint32 or leftover string per decision.
- `pkg/decisionscope/lookup.go`: `LookupCachedRemediation` loops keys, `GetInt` then `GetMany(leftoverKeys)`, merges header scopes, then `membership.Remediation(ipAddr)`.
- `pkg/bouncer/bouncer.go`: stream/alone/live call `LookupCachedRemediation` with `lapiClient.Cache()` and `RangeMembership()`.
- `vendor/.../iplookup/helper.go`: `Helper.Contains` takes `sync.Mutex` (exclusive) on every lookup.
- `pkg/cache/cache.go`: `localCache.get` / `getInt` call `ttl_map.Heap.Get` (expiry can drop entries on read per vendored TTL map).
- OptCOW snapshot type / publish path: not found.

## Desired
- In-memory stream/alone only: on each stream tick (same cadence as range hydrate), build one immutable snapshot: `map[string]uint32` for IP and header-scope keys (packed words) plus existing Range membership snapshot; publish via `atomic.Value`; request path `Load()` only.
- Lookup: single map probe per relevant key on packed path; no leftover `GetMany` on that path; skip Range when IP slot is already ban.
- Range `Contains` on the snapshot must not use exclusive mutex on immutable data (new snapshot trees or lock-free read path).
- TTL: do not rely on write-on-Get expiry; drop expired IP slots when publishing the tick snapshot; one publish per tick, not per stream `Set`.
- Snapshot replaces TTL map as stream/alone memory request-path IP store—no duplicate IP copies in TTL map and snapshot.
- Header scopes remain string keys on the same map; ban wins across Ip, Range, headers (unchanged merge semantics).
- Delivery card: measured heap retained, allocs/op, sequential/parallel miss ns/op vs origin/main with brief why.
- Redis, live, and none modes unchanged on TTL map behavior.

## Affected
- `pkg/lapi/` (client stream tick, snapshot publish, possibly Client fields)
- `pkg/decisionscope/lookup.go` (stream/alone lookup entry or caller)
- `pkg/bouncer/bouncer.go` (ServeHTTP lookup wiring for stream/alone memory)
- `pkg/cache/` (only if stream writer still needs TTL map for lease/range-index or live path—must not duplicate IP store)
- Benchmarks / tests proving perf claims

## Out of scope
- Path-compressed Patricia combining IPs and ranges
- Redis backend changes
- Live negative-cache copy-on-write
- Stuffing individual IPs into uncompressed `iplookup.Helper` as /32s
- Combining header scopes into a radix (stay map keys)

## Unknowns
- Exact split: whether range-index blob and stream lease key stay in TTL map while IP/header words move to snapshot only (ticket implies replace request-path IP store, not necessarily all cache keys).
- How leftover string origins (intern overflow) encode in `map[string]uint32`-only snapshot vs parallel string sidecar—not specified in ticket.
- Benchmark package location and fixture size for card numbers—not specified.

## Tensions
- Ticket forbids write-on-Get TTL for IP slots; current `ttl_map.Heap.Get` may delete expired entries on read (`pkg/cache/cache.go` → vendored heap).
- Ticket wants Range without exclusive mutex on immutable snapshot; current `RangeMembership` uses `iplookup.Helper` with mutex on Contains (`vendor/.../iplookup/helper.go`).
- Stream path still mutates TTL map today while ticket says snapshot replaces it for IPs—incremental stream `Set` per decision vs publish-once-per-tick needs a staging model during the tick.
- `LookupCachedRemediation` is shared with live mode; live must keep TTL map path while stream/alone memory switches to snapshot Load.
