# Requirement
IssueKey: 2026-09-18-range-index-same-network-match

## Problem
Range-index upsert and delete identify a blob line by raw CIDR text. `AddRange(10.1.2.0/8)` stores `10.1.2.0/8=…`. Membership `ParseCIDR`s that line, so `10.1.2.3` is banned. `RemoveRange(10.0.0.0/8)` does not drop that line (`10.1.2.0/8` ≠ `10.0.0.0/8`). Hydrate rebuilds trees from the leftover blob, so the ban stays. The leftover is the unremoved line, not hydrate.

## Current (code)
- `upsertIndexCIDR` replaces only when `existing == cidr` (string). `pkg/decisionscope/range.go`
- `removeCIDRFromIndex` drops only when `network == cidr` (string). `pkg/decisionscope/range.go`
- `ApplyRangeBatch` is one `readRangeIndex`, upsert loop, remove loop, then `Set` or `Delete`. A GET failure that is not `CacheMiss` returns the error and does not write. `pkg/decisionscope/range.go`
- `AddRange` / `RemoveRange` pass `strings.TrimSpace` CIDR text into that batch. Persist is that incoming text, not `(*net.IPNet).String()`. `pkg/decisionscope/range.go`
- Membership already uses `net.ParseCIDR`: `MembershipFromIndex` → `Helper.AddCIDR`. `pkg/decisionscope/rangemembership.go` `pkg/iplookup/iplookup.go`
- Stream hydrate rebuilds in-process trees from the blob after a successful `ApplyRangeBatch`. `pkg/lapi/client_stream.go` `pkg/lapi/client.go`
- `TestRemoveRange` / `TestAddRangeUpdatesRemediation` use identical spellings. No `10.1.2.0/8` then `10.0.0.0/8` case. `pkg/decisionscope/zzz_range_test.go`
- Unread-base apply tests: `TestApplyRangeBatch_UnreachableReadKeepsSharedIndex`, `TestApplyRangeBatch_UnreachableReadDoesNotDeleteIndex`. `pkg/lapi/zzz_ipcachekey_test.go`

## Desired
- In `upsertIndexCIDR` and `removeCIDRFromIndex` only: parse both sides with `net.ParseCIDR`; treat as the same line when masked IP and prefix match (`IP.Equal` + same mask ones/bits, or `Mask.String()`).
- Persist the incoming CIDR text as today. Do not rewrite lines to `(*net.IPNet).String()`.
- Keep master's `ApplyRangeBatch` shape and read-error contract (failed GET, not miss, returns and MUST NOT write an empty/truncated blob).
- One small same-network helper next to the two loops is allowed.
- Test: `AddRange(10.1.2.0/8)` then `RemoveRange(10.0.0.0/8)` clears membership for `10.1.2.3`. Keep existing unread-base apply tests passing.
- Bound to this comparison only.

## Affected
- `pkg/decisionscope/range.go` (`upsertIndexCIDR`, `removeCIDRFromIndex`; optional helper next to those loops)
- `pkg/decisionscope/zzz_range_test.go` (equivalent-network remove after add)
- Existing unread-base tests must still pass: `pkg/lapi/zzz_ipcachekey_test.go`

## Out of scope
- `indexNetworkID`, `collapseRangeUpserts`, `hasParseableIndexCIDR` early-return, dual identity helpers
- Sweep-rewrite of unrelated leftover spellings already in the blob
- Persist rewrite to `(*net.IPNet).String()`
- Metrics slot key changes
- Bare-IP host-prefix work
- IPv4-mapped persist work
- Changing hydrate / `MembershipFromIndex` / `ApplyRangeBatch` read-error shape
- Reusing closed PR #92 or branch `2026-09-18-range-index-cidr-canonical-delete`

## Unknowns
- Which of the two ticket-allowed compare forms this run uses (`IP.Equal` + mask ones/bits vs `Mask.String()`).
- Fallback when either side fails `ParseCIDR` (today identical raw text still matches via `==`).

## Tensions
- Closed PR #92 targeted the same leftover ban but applied extras this ticket forbids (canonical persist, collapse, identity helpers) and predated master's read-error return. This run is a new ticket, not a reopen.
- Ticket allows either mask compare; both must stay next to the two loops and must not rewrite stored text.
