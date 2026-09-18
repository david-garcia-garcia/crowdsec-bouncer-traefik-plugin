# Stream apply

## Language

**Stream apply**:
The write of one CrowdSec `GET /v1/decisions/stream` payload (`new` and `deleted`) into the DecisionStore.
_Avoid_: stream poll, stream lease, ticker

**Same-window replacement**:
A `new` decision and a `deleted` prior for the same Ip value or the same Range CIDR in that one payload.
_Avoid_: two ticks, live lookup

## Overview

After the stream lease is won and the body is decoded, apply deleted first so a same-window replacement stays active. Range stays one `ApplyRangeBatch` (one read, one write). The lease and the intra-Client poll lock are other packets.

## How to use

- Keep GET, decode, and apply in `fetchAndApplyStreamDecisions` so a failed poll still releases `updated` (`core_plugin_lapi_stream-lease.md`).
- Loop `stream.Deleted` first: Ip/header `deleteStreamDecision`, Range CIDRs into removals, `forgetActiveDecision`.
- Then loop `stream.New`: Ip/header `storeStreamDecision`, Range CIDRs into upserts, `rememberActiveDecision`.
- Call `ApplyRangeBatch` once with those maps. Inside the batch, apply removals before upserts so a CIDR in both maps remains the replacement.
- Hydrate Range membership from the blob after the batch.
- Do not GET+SET per Range line. Do not split the batch into two cache writes.

## Pattern snippet

```go
for _, decision := range stream.Deleted {
	// deleteStreamDecision or collect Range removal + forget
}
for _, decision := range stream.New {
	// storeStreamDecision or collect Range upsert + remember
}
decisionscope.ApplyRangeBatch(c.Cache(), rangeUpserts, rangeRemovals)
c.hydrateRangeMembership()
```

## Key files

- `pkg/lapi/client_stream.go`
- `pkg/lapi/client_decisions.go`
- `pkg/decisionscope/range.go`

## Gotchas

- Dest order (New then Deleted, or upserts then removals) drops a same-window replacement: the store is deleted and the client is allowed.
- Header-mapped scopes ride the same loops as Ip; they do not need a separate apply path.
- `ApplyRangeBatch` one-sided callers (`AddRange`, `RemoveRange`) stay equivalent when only one map is non-empty.
- Official vendor apply order lives in `knowledge/research/ext_crowdsec_bouncers_stream-apply/` when that folder exists.
