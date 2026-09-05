## Context

See proposal.md — Why. Today `LookupCachedRemediation` MGETs `range-index` and `MatchRangeFromIndex` walks every line with `ip.InNetwork`. `handleStreamCache` lease hit returns without reading the blob; Redis followers stay correct only because ServeHTTP reads Redis. `pkg/iplookup.Helper` is boolean membership + longest prefix, no payload, no delete. Client IP is `pkg/ip.GetRemoteIP`. Reclaim value is `CrowdsecConnection` (`reclaim.Open`, not `sync.Once`).

## Goals / Non-Goals

**Goals:**
- Request-path Range in stream/alone is prefix-bounded membership on the connection.
- Blob remains the shared document; followers hydrate on the ticker and at stream start.
- Ban wins across overlapping CIDRs without longest-prefix-wins.

**Non-Goals:**
- `SET NX` on `updated`.
- `range-index-gen` key.
- `DeleteCIDR` / incremental tree edits.
- Remediation payload on `iplookup.Helper`.
- Range inside `pkg/ip.Checker`.
- live/none `?ip=` expansion.

## Decisions

1. **`pkg/decisionscope.RangeMembership` owns ban-then-captcha.** Two `iplookup.Helper`s. `MembershipFromIndex` rebuilds from the blob (skip invalid CIDR lines). Alternative: one LPM tree with a stored remediation — rejected; a captcha `/24` would hide a ban `/8`.

2. **`CrowdsecConnection` holds `atomic.Pointer[RangeMembership]`.** Rebuild builds a new pair and stores it. Readers see the previous complete pair or the new one. Alternative: mutex around lookup — extra contention on the request path. Alternative: mutate Helper in place — no delete API.

3. **`LookupCachedRemediation` takes `*RangeMembership`.** `GetMany` omits `RangeIndexKey` in stream/alone. Nil or empty membership is a Range miss. Alternative: connection method that wraps lookup — rejected; matching merge stays in decisionscope.

4. **Hydrate at `startStream` from GET `range-index`.** No extra LAPI poll. `StreamStartupBlock` still controls the first stream poll. Alternative: wait for first ticker — first requests miss Range.

5. **Lease hit still GETs the blob.** Compare raw string to last hydrate; rebuild if different. GET error keeps the last membership. Alternative: generation key — skipped; lists stay small.

6. **Identity:** classify `GetRemoteIP` output (`net.ParseIP` + `IsContained`). Do not parse `RemoteAddr`.

## Risks / Trade-offs

- [Follower lease hit never hydrated] → hydrate on that path; without it Redis replicas miss every Range decision once ServeHTTP stops MGETing the blob.
- [Rebuild vs request race] → atomic pointer swap of a complete pair.
- [Invalid blob CIDR] → skip the line, same as today’s `InNetwork` error skip.
- [Stale membership between ticks] → accepted; same as today’s blob TTL / ticker cadence.
- [Yaegi `for i := range n`] → `iplookup` already uses C-style loops; do not change that package unless tests force it.

## Migration Plan

Plugin version bump. No new YAML keys. Rollback is the previous tag (request path walks the blob again). Redis `range-index` format is unchanged.

## Open Questions

None. Assumed proceed policies live on `devstate/explore.md`.
