# Range active_decisions forget after dropping the slot map

IssueKey: 2026-09-20-store-active-decisions-gauge
Size: large
Action: note

## Why this follow-up

Range is a blob plus LPM trees, not a slot Peek. Stream/alone `active_decisions` should eventually include Range CIDRs labeled origin × ip_type, but exact-CIDR forget needs displacements from `ApplyRangeBatch` (removals then upserts, one walk). Until that lands, omit Range from the store-owned gauge.

## Why it was not taken

Ship Ip/header store-owned counts first. Helper has no public exact-prefix get; do not patch `vendor/.../iplookup`; do not LPM a network IP to fake a CIDR get.

## Risks

`cscli metrics show bouncers` `active_decisions` omits Range CIDRs (accepted). Do not “fix” with `LookupRemediation` or `RangeMembership.Remediation`. Do not keep `activeDecisionSlots` only for `range:` keys.

## Context

Dest stream Range still `rememberActiveDecision("range:"+cidr)` / `forgetActiveDecision("range:"+cidr)` in `pkg/lapi/client_stream.go`. Blob apply is `pkg/decisionstore/range.go` `ApplyRangeIndex`. Membership is `pkg/decisionstore/rangemembership.go`. `Store.Peek` is not found on dest.
