## Why

Ip-scoped cache lookup uses the raw client string while stream store canonicalizes via `IPCacheKey`, so alternate IPv6 spellings and IPv4-mapped forms miss valid bans. Separately, a transient Redis read failure during `ApplyRangeBatch` is treated as an empty range index and can truncate or delete the shared `range-index` blob.

## What Changes

- Add `IpLookupCacheKey(remoteIP, ipAddr)` and use it on the request lookup path so Ip cache keys match stream store canonicalization.
- `readRangeIndex` / `ApplyRangeBatch` propagate read errors; abort write on unreachable (mirror `hydrateRangeMembership`). `CacheMiss` still starts from empty.
- Stream handler skips range apply when read fails.
- Tests for alternate IPv6 spellings, IPv4-mapped headers, and unreachable read before apply.
- **Not BREAKING.** No public config keys. Redis key names unchanged.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisions_scopes`: Ip lookup cache key SHALL match store canonicalization; range-index apply SHALL NOT overwrite on unreachable read.

## Impact

- `pkg/decisionscope/scope.go`, `lookup.go`, `range.go`
- `pkg/lapi/client_stream.go`
- Tests in `pkg/decisionscope`
