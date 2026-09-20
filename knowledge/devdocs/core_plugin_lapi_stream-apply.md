# Stream apply

## Language

**Stream apply**:
The write of one CrowdSec `GET /v1/decisions/stream` payload (`new` and `deleted`) into the DecisionStore.
_Avoid_: stream poll, stream lease, ticker

**Same-window replacement**:
A `new` decision and a `deleted` prior for the same Ip value or the same Range CIDR in that one payload.
_Avoid_: two ticks, live lookup

## Overview

After the body is decoded, apply deleted first so a same-window replacement stays active. Range stays one Store `ApplyRangeBatch` (one read, one write). Intra-Client poll skip is `core_plugin_lapi_stream-single-flight.md`. There is no stream lease.

## How to use

- Keep GET, decode, and apply in `fetchAndApplyStreamDecisions`.
- Call `decisionStore.BeginTick` before the loops and `PublishTick(decisionstore.ElapsedNow())` after (defer). Memory hides tick writes until publish and sweeps tick slots on elapsed `now`. Redis tick is a no-op and ignores `now`.
- Loop `stream.Deleted` first: Ip/header `DeleteMany` in `PutManyChunk` flushes, Range CIDRs into removals.
- Then loop `stream.New`: Ip/header `PutMany` in `PutManyChunk` flushes, Range CIDRs into upserts via `KindOriginString`.
- Call `decisionStore.ApplyRangeBatch` once with those maps. Inside the batch, apply removals before upserts so a CIDR in both maps remains the replacement.
- Hydrate Range membership from the store after the batch (`HydrateRange` at stream start; membership follows the blob).
- Do not GET+SET per Range line. Do not split the batch into two store writes. Do not acquire `updated`.

## Pattern snippet

```go
c.decisionStore.BeginTick()
defer c.decisionStore.PublishTick(decisionstore.ElapsedNow())
for _, decision := range stream.Deleted {
	// streamDeleteItem + DeleteMany (PutManyChunk flushes) or collect Range removal
}
for _, decision := range stream.New {
	// streamPutItem + PutMany (PutManyChunk flushes) or collect Range upsert
}
if err := c.decisionStore.ApplyRangeBatch(rangeUpserts, rangeRemovals); err != nil {
	return err
}
```

## Key files

- `pkg/lapi/client_stream.go`
- `pkg/lapi/client_decisions.go`
- `pkg/decisionstore/range.go`

## Gotchas

- Dest order (New then Deleted, or upserts then removals) drops a same-window replacement: the store is deleted and the client is allowed.
- On memory, `PublishTick` takes int32 elapsed seconds (`decisionstore.ElapsedNow()`), not wall Unix; mixing clocks drops every slot on publish.
- Header-mapped scopes ride the same loops as Ip; they do not need a separate apply path.
- `ApplyRangeBatch` one-sided callers stay equivalent when only one map is non-empty.
- Official vendor apply order lives in `knowledge/research/ext_crowdsec_bouncers_stream-apply/` when that folder exists.
