# Requirement
IssueKey: 2026-09-18-stream-apply-deleted-before-new

## Problem
On dest `fad36a1`, `fetchAndApplyStreamDecisions` writes `stream.New` (IP/header store and Range upserts) before `stream.Deleted` (IP/header delete and Range removals). A same-window replacement — LAPI sends a new ban and deletes the prior decision for the same IP or CIDR — stores then deletes, so the replacement disappears and the client is allowed. Official CrowdSec bouncers are claimed to apply deleted first. Bound to this apply-order defect only.

## Current (code)
- `fetchAndApplyStreamDecisions` loops `stream.New` first: Range values go into `rangeUpserts` and `rememberActiveDecision`; other scopes call `storeStreamDecision`. `pkg/lapi/client_stream.go`
- The same function then loops `stream.Deleted`: Range values go into `rangeRemovals` and `forgetActiveDecision`; other scopes call `deleteStreamDecision`. `pkg/lapi/client_stream.go`
- After both loops it calls `ApplyRangeBatch(c.Cache(), rangeUpserts, rangeRemovals)` then `hydrateRangeMembership`. `pkg/lapi/client_stream.go`
- `ApplyRangeBatch` upserts every CIDR, then applies removals, so a CIDR present in both maps is removed. `pkg/decisionscope/range.go`
- `storeStreamDecision` Sets the IP slot or a live header-scope slot. Range returns without writing. `pkg/lapi/client_decisions.go`
- `deleteStreamDecision` Deletes the IP slot (and the raw value key) or a header-scope slot. Range returns without writing. `pkg/lapi/client_decisions.go`
- Dest stream tests cover lease, failure release, and poll overlap. They do not cover same-window replacement. `pkg/lapi/zzz_client_stream_test.go` `pkg/lapi/zzz_client_stream_overlap_test.go`
- `TestHunt_StreamAppliesDeletedBeforeNew` and `TestHunt_StreamRangeAppliesDeletedBeforeNew`: not found on dest.

## Desired
- Apply deleted first: IP/header `deleteStreamDecision` and Range removals before IP/header `storeStreamDecision` and Range upserts.
- After a one-payload replacement (new ban + deleted prior for the same IP or the same CIDR), the replacement remediation must remain active.
- Include regression tests for IP and Range that fail on dest order and pass after the swap.
- Do not widen the ticket.

## Affected
- `pkg/lapi/client_stream.go` (`fetchAndApplyStreamDecisions`)
- `pkg/decisionscope/range.go` only if `ApplyRangeBatch` must apply removals before upserts for this batch
- `pkg/lapi/zzz_client_stream_test.go` or a sibling `zzz_` stream test file
- Stream apply spec / usage if propose folds this invariant onto an existing LAPI stream leaf

## Out of scope
- Stream lease, single-flight, health flags, `updated` TTL
- Live/none lookup, AppSec, captcha, reclaim, metrics reporter
- Changing `AddRange` / `RemoveRange` call sites except as required for batch order
- A header-scope-only hunt test (ticket asked IP and Range regressions; header delete/store rides the same loops)
- Reordering LAPI JSON fields or the `Stream` struct
- Official CrowdSec bouncer repos

## Unknowns
- Whether official CrowdSec bouncers still apply deleted first (ticket claim; no `knowledge/research/` finding this prepare).
- Whether LAPI emits same-window replacements in production at this dest pin (ticket treats that as given).
- Whether the IP/Range regressions land in `zzz_client_stream_test.go` or a new `zzz_` file (propose).

## Tensions
- Ticket line numbers `client_stream.go:122-149` match dest `fad36a1` (New loop then Deleted loop then `ApplyRangeBatch`).
- Ticket cites hunt tests as proven FAIL; those names are not on dest.
- Ticket says official bouncers apply deleted first; that fact is not in `knowledge/research/` and was not cloned this prepare (no nested research subagent).
- Swapping only the two loops in `fetchAndApplyStreamDecisions` is not enough for Range: `ApplyRangeBatch` still upserts then removes. Desired Range order needs removals before upserts inside that batch or two batch calls.
- `deleteStreamDecision` also Deletes the raw IP value key; that extra key is unchanged by apply order.
