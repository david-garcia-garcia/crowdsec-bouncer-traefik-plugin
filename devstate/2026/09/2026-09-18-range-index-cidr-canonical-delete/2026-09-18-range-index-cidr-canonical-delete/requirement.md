# Requirement
IssueKey: 2026-09-18-range-index-cidr-canonical-delete

## Problem
Range-index upsert and delete identify a line by CIDR text, not by the network. After `AddRange(10.1.2.0/8)`, `RemoveRange(10.0.0.0/8)` leaves `10.1.2.3` banned. Proven FAIL: `TestHunt_RemoveRangeEquivalentCIDRSpelling`.

## Current (code)
- `upsertIndexCIDR` replaces a line only when `existing == cidr` (string). `pkg/decisionscope/range.go`
- `removeCIDRFromIndex` drops a line only when `network == cidr` (string). `pkg/decisionscope/range.go`
- `AddRange`, `RemoveRange`, and `ApplyRangeBatch` pass `strings.TrimSpace` CIDR text into those helpers. No `net.ParseCIDR`. `pkg/decisionscope/range.go`
- Request membership still matches by network: `MembershipFromIndex` calls `helper.AddCIDR`, which `net.ParseCIDR`s and inserts the block, so `10.1.2.0/8` still bans `10.1.2.3`. `pkg/decisionscope/rangemembership.go` `pkg/iplookup/iplookup.go`
- `TestRemoveRange` and `TestAddRangeUpdatesRemediation` use identical spellings. No equivalent-CIDR delete/upsert case. `pkg/decisionscope/zzz_range_test.go`
- `TestHunt_RemoveRangeEquivalentCIDRSpelling` is not in this tree. `not found`
- `IPCacheKey` canonicalizes only Ip host prefixes (`/32` `/128`). It does not identify Range-index lines. `pkg/decisionscope/scope.go`

## Desired
- Upsert and remove Range-index lines by canonical `net.IPNet` (network address + prefix length).
- Include a regression test (the hunt name is acceptable).
- Bound to this defect only.

## Affected
- `pkg/decisionscope/range.go`
- `pkg/decisionscope/zzz_range_test.go` (or a sibling `zzz_` test)
- `openspec/specs/core_plugin_decisions_scopes/spec.md` if propose folds a canonical-line identity requirement
- `knowledge/devdocs/core_plugin_decisionscope.md` if usage must name the write-side identity

## Out of scope
- #77 / #34 Ip cache-key canonicalization (`IPCacheKey`, `IPLookupCacheKey`, live memo key)
- #77 / #34 range-index apply-guard (propagate non-miss read errors)
- Sibling `2026-09-18-range-bare-ip-host-prefix`
- Changing `range-index` key name, request-path membership, or LAPI `?ip=`

## Unknowns
- Whether unparseable CIDR text is stored verbatim or dropped (membership already skips `AddCIDR` errors).
- Whether a later batch rewrites leftover non-canonical spellings already in the blob, or only the network being upserted/removed.

## Tensions
- Ticket line numbers match dest `fad36a1` (`upsertIndexCIDR` 68, `removeCIDRFromIndex` 94–108).
- Hunt test name is the proof, not an in-tree file.
- Spec “Lookup keys MUST NOT change” names the cache keys (`range-index`, client IP, `scope:value`), not the CIDR text inside the blob.
- `storedByCIDR` keys by the blob’s CIDR string; a canonical write changes that string after the next hydrate, not request-path containment.
