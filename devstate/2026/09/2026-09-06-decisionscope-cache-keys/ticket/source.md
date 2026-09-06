# Ip lookup uses raw remoteIP while stream stores IPCacheKey; range index wipe on read error

## Problem

1. Stream stores Ip decisions under `IPCacheKey(...)`; lookup queries raw `remoteIP`. Alternate IPv6 spellings or IPv4-mapped forms can miss cached bans.
2. `readRangeIndex` treats any cache error as empty; `ApplyRangeBatch` can write a truncated index to Redis after a transient read failure.

## Evidence

Sibling findings incorporated:

### ip-cache-key-lookup-store-mismatch

Stream decisions for Ip scope are written under `IPCacheKey(decision.Value)`, which collapses host-prefix CIDRs (`/32`, `/128`) to `net.IP.String()`. Request-path lookup keys the same cache with the raw `remoteIP` string from forwarded headers or `RemoteAddr`, without parsing or canonicalization. When the request string and the stored key use different spellings of the same address, the bouncer misses a valid ban/captcha even though `ipAddr` parses correctly and Range membership may still match.

Evidence paths cited in finding:
- pkg/lapi/client_decisions.go:35 — store uses `IPCacheKey(item.Value)`
- pkg/decisionscope/scope.go:122-133 — `IPCacheKey` canonicalizes `/32`, `/128` only
- pkg/decisionscope/lookup.go:68-73 — lookup reads `found[remoteIP]`
- pkg/decisionscope/lookup.go:94-95 — `LookupCacheKeys` uses `remoteIP` verbatim
- pkg/bouncer/bouncer.go:131-168 — `GetRemoteIP` supplies raw text and parsed `ipAddr`; lookup uses only `remoteIP` for Ip key

### range-index-read-error-wipes-cidrs

`ApplyRangeBatch` reads the shared `range-index` blob through `readRangeIndex`, which returns an empty string on any cache error, including `cache:unreachable`. A transient Redis read failure during a stream update is indistinguishable from a genuinely empty index. The batch then upserts/removes against that empty base and writes the result back, permanently dropping every other Range decision from the shared index until the next full stream resync.

Evidence paths cited in finding:
- pkg/decisionscope/range.go:86-91 — `readRangeIndex` returns `""` on any error
- pkg/decisionscope/range.go:28-43 — `ApplyRangeBatch` writes without checking read success
- pkg/lapi/client_stream.go:127 — stream calls `ApplyRangeBatch` after each poll
- pkg/lapi/client.go:329-334 — `hydrateRangeMembership` skips rebuild on unreachable (non-destructive)
- pkg/cache/cache.go:24-27 — `CacheMiss` and `CacheUnreachable` are distinct

## Current behavior

Cache key form is not symmetrical. A Redis GET error can delete the range index on the next apply.

## Desired

Lookup and store use the same Ip cache key (canonical form). Do not apply an empty range index when the previous index could not be read. Tests for IPv6 spelling/mapped forms and read-error apply.

## Out of scope

Range membership longest-prefix (tested). Header Country/AS normalization.
