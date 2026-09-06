# Explore
IssueKey: 2026-09-06-decisionscope-cache-keys

## Concepts

- **Ip cache key symmetry**: Stream store uses `IPCacheKey(decision.Value)` which collapses `/32` and `/128` to `net.IP.String()`. Request lookup currently uses raw `remoteIP` from headers/`RemoteAddr`, so alternate IPv6 spellings or IPv4-mapped forms miss cached Ip decisions.
- **Range index read failure**: `readRangeIndex` swallows all `Get` errors as empty string. `ApplyRangeBatch` then writes a truncated or deleted `range-index`, unlike `hydrateRangeMembership` which keeps stale membership on unreachable.
- **Identity owner**: `pkg/ip.GetRemoteIP` already yields both raw `remoteIP` string and parsed `ipAddr`. Lookup should canonicalize using parsed `ipAddr` when CIDR parse of the raw string does not produce a store-equivalent key.

## Decisions

- Add `IpLookupCacheKey(remoteIP string, ipAddr net.IP) string` in `pkg/decisionscope`: use `IPCacheKey(remoteIP)` when it differs from trimmed raw (CIDR path); else when `ipAddr != nil` use `To4()`-collapsed `ipAddr.String()`; else trimmed raw. Reuse in `LookupCacheKeys` and result read in `LookupCachedRemediation`.
- Change `readRangeIndex` to `(string, error)`: `CacheMiss` → empty index, nil error; any other error → propagate. `ApplyRangeBatch` returns `error` and aborts write on read failure. `AddRange`/`RemoveRange` ignore the error (test/convenience wrappers). `client_stream.go` logs and skips apply on error (mirror hydrate unreachable behavior).
- Fold spec delta into existing `core_plugin_decisions_scopes` (Ip lookup key + range-index apply safety).

## Open questions

- Q: Whether callers beyond `client_stream.go` need signature changes if `ApplyRangeBatch` returns an error?
  Decision: assumed — only `ApplyRangeBatch` and internal `readRangeIndex` propagate error; `AddRange`/`RemoveRange` stay void; stream handler checks error and returns without writing.
  By: explore

- Q: Exact canonicalization policy for bare IPv6 strings that are not valid CIDR notation but parse as IP?
  Decision: assumed — when `IPCacheKey(remoteIP)` equals trimmed raw (no CIDR canonicalization), fall back to `ipAddr.String()` with IPv4-mapped collapsed via `To4()` when `ipAddr != nil`.
  By: explore

- Q: Who owns client IP canonical form for cache lookup?
  Decision: resolved — `pkg/ip.GetRemoteIP` owns parse; `decisionscope` consumes `ipAddr` for lookup key derivation, does not re-parse headers.
  By: explore
