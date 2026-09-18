# Explore
IssueKey: 2026-09-18-stream-apply-deleted-before-new

## Concepts

**Stream apply** is the write of one CrowdSec `GET /v1/decisions/stream` payload (`Stream.New` + `Stream.Deleted`) into the DecisionStore. It is not the `updated` lease (`core_plugin_lapi_stream-lease`) and not the intra-Client poll lock (`core_plugin_lapi_stream-single-flight`).

**Same-window replacement** is one payload that both deletes a prior decision and adds a new one for the same Ip value or the same Range CIDR (typical: expire/replace a ban). Dest `fad36a1` stores then deletes, so the replacement is gone and the client is allowed.

Dest apply in `pkg/lapi/client_stream.go` `fetchAndApplyStreamDecisions`:

```
GET stream ─► loop New (store / collect rangeUpserts + remember)
           ─► loop Deleted (delete / collect rangeRemovals + forget)
           ─► ApplyRangeBatch(upserts, removals)  ─► hydrateRangeMembership
```

`ApplyRangeBatch` (`pkg/decisionscope/range.go`) upserts every CIDR, then applies removals. A CIDR in both maps is removed. Swapping only the two loops is not enough for Range.

`rememberActiveDecision` / `forgetActiveDecision` ride the same loops. Dest remember-then-forget also drops the replacement from the usage-metrics gauge.

Official CrowdSec bouncer apply order was not in `knowledge/research/` at explore start. Research is in flight (`ext_crowdsec_bouncers_stream-apply/`). This run still applies deleted first because dest code plus the ticket bound prove the replacement disappears.

Hunt tests `TestHunt_StreamAppliesDeletedBeforeNew` and `TestHunt_StreamRangeAppliesDeletedBeforeNew` are not on dest. Existing stream tests cover lease, failure release, and poll overlap only (`pkg/lapi/zzz_client_stream_test.go`, `zzz_client_stream_overlap_test.go`).

This work does not reconstruct client address, user, tenant, Host, or trust hop. No Traefik `New` / reclaim / `sync.Once` change.

## Decisions

- Bound: swap apply order only. Do not touch lease, single-flight, live/none, AppSec, captcha, reclaim, or LAPI JSON shape.
- Ip/header: loop `stream.Deleted` (`deleteStreamDecision`) before `stream.New` (`storeStreamDecision`).
- Range: apply removals before upserts inside the existing one-read/one-write `ApplyRangeBatch`. Do not split into two batch calls (that would break the Range-index write invariant).
- Metrics book-keeping: forget on delete, then remember on store, as a consequence of the same loop swap.
- Spec host (propose FindSpecHost): new leaf `core_plugin_lapi_stream-apply` beside `stream-lease` / `stream-single-flight`. Do not fold into `core_plugin_lapi_stream-lease` (lease ≠ apply) or `core_plugin_decisions_scopes` (match ≠ apply).
- Tests: add the two hunt names on dest in `pkg/lapi/zzz_client_stream_test.go` (helpers already live in this package). Stub a one-payload replacement; assert the Ip slot / Range membership stays banned. No header-only hunt (header delete/store rides the same loops).
- Usage: new packet `core_plugin_lapi_stream-apply.md`; existing lease / decisionscope packets point at it.

## Open questions

- Q: Do official CrowdSec bouncers still apply deleted first?
  Decision: assumed — apply deleted first anyway; dest replacement disappears regardless. Research folder `ext_crowdsec_bouncers_stream-apply/` is writing the vendor fact.
  By: explore

- Q: Does production LAPI emit same-window replacements at this dest pin?
  Decision: assumed — ticket treats that as given; regressions inject that payload and do not depend on a live LAPI.
  By: explore

- Q: Do the IP/Range regressions land in `zzz_client_stream_test.go` or a new `zzz_` file?
  Decision: assumed — same file; package already has `newTestRangeClient` / `newTestStreamPoller` and `std_go_test_zzz-prefix` is satisfied.
  By: explore

- Q: Should `ApplyRangeBatch` change internal order, or should stream call it twice?
  Decision: assumed — change internal order (removals then upserts). One-sided `AddRange` / `RemoveRange` call sites stay equivalent.
  By: explore
