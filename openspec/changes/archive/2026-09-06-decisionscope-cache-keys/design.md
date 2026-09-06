See proposal.md — Why.

## Approach

1. **`IpLookupCacheKey`**: When `IPCacheKey(remoteIP)` differs from trimmed raw (CIDR canonicalization), use that key. Otherwise when `ipAddr != nil`, use `To4()`-collapsed `ipAddr.String()`. Else trimmed raw. `LookupCacheKeys` and `LookupCachedRemediation` use this for the Ip slot.

2. **Range index read**: `readRangeIndex` returns `(string, error)`. `CacheMiss` → `("", nil)`. Other errors propagate. `ApplyRangeBatch` returns `error` and skips `Set`/`Delete` on read failure. `AddRange`/`RemoveRange` ignore error (convenience). `handleStreamCache` checks error before `hydrateRangeMembership`.

3. **Tests**: Store under `IPCacheKey` with `/128` and `/32`; lookup with expanded IPv6 and `::ffff:` mapped form. Stub cache returning `CacheUnreachable` on `Get(RangeIndexKey)`; assert index unchanged after apply attempt.

## Alternatives considered

- Extend `IPCacheKey` to parse bare IPs — rejected; lookup already has `ipAddr` from GetRemoteIP; keep store path unchanged.
