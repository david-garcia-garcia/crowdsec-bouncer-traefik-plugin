# Requirement
IssueKey: 2026-09-06-decisionscope-cache-keys

## Problem

Ip-scoped cache lookup can miss valid stream decisions when request `remoteIP` text differs from the canonical key used at store time (IPv6 compressed vs expanded, IPv4-mapped forms). Separately, a transient Redis read failure during `ApplyRangeBatch` is treated as an empty range index and can overwrite or delete the shared `range-index` blob, dropping unrelated Range decisions.

## Current (code)

- `pkg/lapi/client_decisions.go:35,60` — stream store/delete use `decisionscope.IPCacheKey(item.Value)` for Ip scope.
- `pkg/decisionscope/scope.go:122-133` — `IPCacheKey` canonicalizes only when `net.ParseCIDR` succeeds with full host prefix (`/32`, `/128`); bare strings are trimmed, not parsed to `net.IP.String()`.
- `pkg/decisionscope/lookup.go:68-73,86-87` — `LookupCachedRemediation` queries and reads results under raw `remoteIP`.
- `pkg/decisionscope/lookup.go:93-95` — `LookupCacheKeys` puts `remoteIP` verbatim as the Ip cache key.
- `pkg/bouncer/bouncer.go:131-168` — `GetRemoteIP` returns raw header/`RemoteAddr` text plus parsed `ipAddr`; lookup receives both but Ip keying uses only `remoteIP`.
- `pkg/decisionscope/scope_test.go:92-98` — `TestIPCacheKey` covers bare IPv4 and `/32` only; no alternate IPv6 or mapped forms.
- `pkg/decisionscope/range.go:86-91` — `readRangeIndex` returns `""` on any `Get` error (miss, unreachable, other).
- `pkg/decisionscope/range.go:28-43` — `ApplyRangeBatch` mutates that index and `Set`/`Delete`s `RangeIndexKey` without distinguishing read failure from empty index.
- `pkg/lapi/client_stream.go:127` — each stream poll calls `ApplyRangeBatch`.
- `pkg/lapi/client.go:329-334` — `hydrateRangeMembership` keeps stale in-process membership on unreachable read (non-destructive); blob path is destructive.
- `pkg/cache/cache.go:24-27` — `CacheMiss` and `CacheUnreachable` are distinct error strings.
- `pkg/decisionscope/range_test.go` — no case where `Get(RangeIndexKey)` returns unreachable before apply.

## Desired

Derive Ip cache lookup keys the same way stream store does (e.g. `IPCacheKey(remoteIP)` when parseable, else `ipAddr.String()` with IPv4-mapped collapsed when `ipAddr != nil`, else `remoteIP`). Propagate read errors from `readRangeIndex` / `ApplyRangeBatch` and abort writes when the existing index could not be loaded; distinguish `CacheMiss` (start empty) from `CacheUnreachable` (fail closed). Add tests for alternate IPv6 spellings, IPv4-mapped headers, and unreachable read before range apply.

## Affected

- `pkg/decisionscope/lookup.go` — Ip cache key derivation and result lookup.
- `pkg/decisionscope/range.go` — `readRangeIndex`, `ApplyRangeBatch`, callers (`AddRange`, `RemoveRange`).
- `pkg/lapi/client_stream.go` — handle `ApplyRangeBatch` error from unreachable read.
- Tests: `pkg/decisionscope/scope_test.go`, `pkg/decisionscope/range_test.go`, lookup tests as needed.

## Out of scope

- Range CIDR membership via `RangeMembership` / longest-prefix (already consistent with parsed `ipAddr`).
- Header-scope key normalization (`HeaderScopeKey`) — already symmetric on store and request paths.
- Bare IPv4 strings that already match exactly on store and lookup.
- In-process membership staleness on unreachable read in `hydrateRangeMembership` (already non-destructive).
- Local-only cache mode where `Get` never returns `CacheUnreachable`.

## Unknowns

- Whether callers beyond `client_stream.go` need signature changes if `ApplyRangeBatch` returns an error.
- Exact canonicalization policy for bare IPv6 strings that are not valid CIDR notation but parse as IP (ticket suggests `ipAddr.String()` fallback).

## Tensions

- Ticket asks for `ipAddr.String()` / `To4()` fallback when CIDR parse fails; current `IPCacheKey` does not parse bare addresses — lookup fix may need a small helper beyond reusing `IPCacheKey` alone.
- `deleteStreamDecision` also deletes raw `item.Value` (`pkg/lapi/client_decisions.go:63`) — legacy dual-key cleanup, not part of ticket desired scope but may affect miss behavior for old entries.
