# Requirement
IssueKey: 2026-09-18-ip-cache-key-canonicalization

## Problem

1. **Ip cache keys are asymmetric.** The plugin writes an Ip-scope cache entry under one textual
   spelling of an address and reads it under another, so the entry is missed. `IPCacheKey` only
   canonicalizes when `net.ParseCIDR` succeeds on a host prefix (`/32`, `/128`); a bare decision
   value is stored verbatim. The request path keys on the raw `remoteIP` text taken from
   `RemoteAddr` or the forwarded header. CrowdSec stores decision values verbatim (measured), so
   arbitrary spellings really do arrive.
2. **The range-index apply can wipe the shared index.** `readRangeIndex` collapses every cache
   error to `""`, so an unreachable read is indistinguishable from an empty index.
   `ApplyRangeBatch` then rebuilds from empty and writes a truncated blob — or deletes the key.

## Current (code)

- `pkg/decisionscope/scope.go:122-133` — `IPCacheKey` returns the trimmed value when
  `net.ParseCIDR` fails, so bare addresses are never canonicalized.
- `pkg/lapi/client_decisions.go:36,61` — stream store/delete key on `IPCacheKey(item.Value)`.
- `pkg/lapi/client_live.go:45,56` — live-mode memo writes key on the raw `remoteIP`.
- `pkg/decisionscope/lookup.go:76,81,92,99-100` — the request path keys on the raw `remoteIP`.
- `pkg/bouncer/bouncer.go:156,192` — `ip.GetRemoteIP` already yields both the raw string and the
  parsed `net.IP`, and both already reach `LookupCachedRemediation`.
- `pkg/decisionscope/range.go:85-91` — `readRangeIndex` returns `""` on any error.
- `pkg/decisionscope/range.go:23-44` — `ApplyRangeBatch` writes from that base unconditionally.
- `pkg/lapi/client_stream.go:149` — every successful stream poll calls `ApplyRangeBatch`.
- `pkg/cache/cache.go:101-117` vs `pkg/cache/acquire.go:47-49` — `get` runs on a round-robin
  **reader**, `acquire` runs on the **writer**.

## Desired

One canonicalization rule for Ip cache keys, applied on the write side and the read side in the
same commit. Live-mode caching must still hit after the change. `readRangeIndex` must separate
`CacheMiss` from a real read failure, and `ApplyRangeBatch` must not write from a base it could
not read.

## Affected

- `pkg/decisionscope/scope.go`, `lookup.go`, `range.go`
- `pkg/lapi/client_live.go`, `client_stream.go`
- Tests in `pkg/decisionscope` and `pkg/lapi`

## Out of scope

- Non-IP scopes. Country and AS values are not addresses and keep their own normalization.
- Range decisions, which are served by the range index, not by exact-key lookups.
- Any new configuration knob.
- A cache migration. Entries written under the old spelling expire by TTL.

## Unknowns

- Whether an aborted range apply should fail the whole poll or only skip the write.
