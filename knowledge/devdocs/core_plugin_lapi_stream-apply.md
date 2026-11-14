# Stream apply

## Language

**Stream apply**:
The write of one CrowdSec `GET /v1/decisions/stream` payload (`new` and `deleted`) into the DecisionStore.
_Avoid_: stream poll, stream lease, ticker

**Same-window replacement**:
A `new` decision and a `deleted` prior for the same Ip value or the same Range CIDR in that one payload.
_Avoid_: two ticks, live lookup

**Remediation fallback**:
The store letter (`lapiRemediationFallback`: ban, captcha, or not stored under ignore) the LAPI connection gives a decision type that is neither `ban` nor `captcha`.
_Avoid_: passthrough, whitelist, allow, failure action

## Overview

After the body is decoded, apply deleted first so a same-window replacement stays active. Range stays one Store `ApplyRangeBatch` (one read, one write). Intra-Client poll skip is `core_plugin_lapi_stream-single-flight.md`. There is no stream lease.

## How to use

- Keep GET, decode, and apply in `fetchAndApplyStreamDecisions`.
- Call `decisionStore.BeginTick` before the loops and `PublishTick(decisionstore.ElapsedNow())` after (defer). Memory hides tick writes until publish, sweeps tick slots on elapsed `now`, then recounts `ActiveCounts` from the published map. Redis tick is a no-op and ignores `now`.
- Loop `stream.Deleted` first: Ip/header `DeleteMany` in `PutManyChunk` flushes, Range CIDRs into removals. Ask `deletedTypeClearsStore(type)` on both shapes: under fallback `ignore` an unknown-type Deleted row deletes nothing; under `ban` / `captcha` it still clears the whole slot or CIDR (multi-decision debt).
- Count only rows written: skipped New or Deleted rows do not add to `newCount` / `deletedCount`.
- Then loop `stream.New`: Ip/header `PutMany` in `PutManyChunk` flushes, Range CIDRs into upserts via `KindOriginString`. Map kind with `ingestRemediationKind` after `MetricsOrigin` (`RemediationValue` for ban/captcha; any other type follows the remediation fallback and TRACE-logs `handleStreamCache:unknownType` with `type` and `fallback`). An empty kind (fallback `ignore`) is not stored: `streamPutItem` returns false and the Range New branch skips the CIDR. `streamPutItem` copies LAPI `item.Scenario` onto `Decision.Scenario` and keeps `Origin` as `MetricsOrigin`. Range upserts stay letter plus folded origin. Do not write a packed intern id into Redis or the Range blob. `OriginBasedDecisionRemap` is Bouncer apply (`core_plugin_lapi_origin-based-decision-remap.md`), not a store rewrite. Do not change `RemediationValue`.
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
- `lapiRemediationFallback` is read from the opener in `lapi.New`; a subscriber's value is unused. It is not `bouncerLapiFailureAction` (LAPI unreachable).
- `whitelist` and `allow` are not valid CrowdSec decision types and are an inadequate way to manage whitelists: the LAPI stream says WHAT TO BLOCK, not WHAT TO ALLOW. They follow the remediation fallback like any unknown type and never lift a ban. Allowing traffic belongs to parser whitelists and LAPI allowlists (`cscli allowlists`), which stop or expire decisions at the source (`knowledge/research/ext_crowdsec_allowlists/`).
- Official vendor apply order lives in `knowledge/research/ext_crowdsec_bouncers_stream-apply/` when that folder exists.
