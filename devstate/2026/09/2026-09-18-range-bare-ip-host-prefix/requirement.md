# Requirement
IssueKey: 2026-09-18-range-bare-ip-host-prefix

## Problem
A Range decision whose host value is a parseable bare IP is written onto `range-index` and then skipped, so that address is never remediated.

## Current (code)
- `ApplyRangeBatch` upserts any non-empty trimmed string; it does not require a slash or `ParseCIDR`. `pkg/decisionscope/range.go`
- Stream copies `decision.Value` into that upsert map as trimmed text. `pkg/lapi/client_stream.go`
- `MembershipFromIndex` calls `helper.AddCIDR(network)` and continues on error, so a stored bare IP never enters the tree. `pkg/decisionscope/rangemembership.go`
- `iplookup.Helper.AddCIDR` is `net.ParseCIDR` only. `pkg/iplookup/iplookup.go`
- `storedMatchingPrefix` also uses `net.ParseCIDR` on the stored key; a bare stored key cannot win a prefix match even if the tree had it. `pkg/decisionscope/rangemembership.go`
- Trusted-pool `NewChecker` maps a parseable bare IP through `hostCIDR` to `/32` or `/128` before `AddCIDR`. `pkg/ip/checker.go`
- Dest spec treats a Range `value` as a CIDR. `openspec/specs/core_plugin_decisions_scopes/spec.md`
- Dest tests cover CIDR upsert/membership and skip `not-a-cidr`; they do not assert a bare Range host remediates. `pkg/decisionscope/zzz_range_test.go` `pkg/decisionscope/zzz_rangemembership_test.go`
- Hunt proof `TestHunt_RangeBareIPIsHostPrefix` is not on dest. `not found`

## Desired
- A parseable bare IP used as a Range host value remediates that address as `/32` or `/128` (same host-prefix rule as the trusted pool).
- Include a regression test.
- This defect only.

## Affected
- `pkg/decisionscope/range.go`
- `pkg/decisionscope/rangemembership.go`
- `pkg/decisionscope` Range tests
- `openspec/specs/core_plugin_decisions_scopes/spec.md` if the CIDR wording must name a host prefix

## Out of scope
- Changing trusted-pool `hostCIDR` itself
- Garbage / unparseable Range values (still skip)
- live/none `?ip=` expansion
- Equivalent-CIDR spelling, IPv4-mapped insert, header scopes
- Other hunt cases

## Unknowns
- Whether the blob is rewritten to `/32` or `/128` on upsert, or only membership treats a bare IP as a host prefix (delete of the original spelling must still drop the line).
- Whether dest must add an explicit host-prefix scenario on the Range spec, or only a regression test.

## Tensions
- Spec says treat Range `value` as a CIDR; CrowdSec persist (`csnet.NewRange`) already accepts bare IP or CIDR. `knowledge/research/ext_crowdsec_decisions_scopes/notes.md`
- `TestMembershipFromIndexSkipsInvalidCIDR` is for `not-a-cidr`, not a parseable host.
- Unexported `ip.hostCIDR` cannot be called from `decisionscope`; reuse the rule, not the symbol.
