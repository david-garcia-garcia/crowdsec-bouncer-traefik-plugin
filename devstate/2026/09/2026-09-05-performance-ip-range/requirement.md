# Requirement
IssueKey: 2026-09-05-performance-ip-range

## Problem

Stream and alone Range matching walks the shared `range-index` blob (`cidr=remediation` lines) on every request. Redis `GetMany` fetches that whole blob with the client IP. Cost is O(n) CIDR tests; the common path is a miss, so the list is always walked. Miss at n=4096 is hundreds of microseconds vs tens of nanoseconds for `pkg/iplookup`.

## Current (code)

- Request lookup in stream/alone always includes `RangeIndexKey` in `GetMany` and walks the blob with `ip.InNetwork` per line. Ban wins if several CIDRs contain the IP. Path: `pkg/decisionscope/lookup.go` (`LookupCachedRemediation`, `LookupCacheKeys`), `pkg/decisionscope/range.go` (`MatchRangeFromIndex`).
- ServeHTTP calls that lookup. Path: `pkg/bouncer/bouncer.go`.
- Stream ticker: `handleStreamCache` GETs cache key `updated`. Hit → return (skip LAPI, skip range-index). Miss → SET `updated` TTL `UpdateIntervalSeconds-1` (min 1), GET `/v1/decisions/stream`, write IP keys, `ApplyRangeBatch` into `range-index`. Path: `pkg/crowdsecconnection/connection.go`.
- Followers with Redis never see `stream.New` / `stream.Deleted`. They match Range today because the request path reads the Redis blob. Same file, lease-hit return.
- `CrowdsecConnection` holds `cacheClient`; no in-process Range tree. `Close()` drops the cache with the connection. Path: `pkg/crowdsecconnection/connection.go`.
- live/none skip `range-index` and expand Range via LAPI `?ip=`. Path: `pkg/decisionscope/lookup.go` (`useRangeIndex`); test `TestLookupCachedRemediationNoneSkipsRangeIndex` in `pkg/decisionscope/range_test.go`.
- Trusted-IP membership already uses `pkg/iplookup.Helper` (boolean + longest prefix, no payload, no delete). Range was left as the linear walk. Path: `pkg/ip/ip.go`, `pkg/iplookup/iplookup.go`, `knowledge/devdocs/core_plugin_ip.md`, `openspec/specs/core_plugin_ip_radix-lookup/spec.md` requirement "Range remediation stays a per-network walk".
- Decision-scope Language Avoid currently names radix tree on the request path. Path: `knowledge/devdocs/core_plugin_decisionscope.md`.
- LAPI stream cursor is per bouncer row (hashed key + client IP), not per API-key string. Finding is in the caller workspace at `knowledge/research/ext_crowdsec_lapi_stream-cursor/` (not on `origin/master`). Dest already has `knowledge/research/ext_crowdsec_decisions_scopes/`.

## Desired

- Keep `range-index` as the durable shared document (Redis or local map). Add an in-process radix used only on the stream/alone request path.
- Tree lives on `CrowdsecConnection` next to `cacheClient`. Rebuild under that connection’s ticker. `Close()` drops it. No `sync.Once` / package globals.
- `LookupCachedRemediation` does `GetMany` without `RangeIndexKey`. Range hit is the local tree, not `MatchRangeFromIndex` on a blob. Ban still wins across Ip / Range / header via `PreferRemediation`. Empty tree = miss (same as empty blob).
- Two boolean `iplookup.Helper`s (ban CIDRs, captcha CIDRs). Do not put a remediation payload on one LPM tree (a captcha `/24` must not hide a ban `/8`). Do not put Range membership in `pkg/ip.Checker`.
- Rebuild from the blob; do not add `DeleteCIDR` this change. IPv4/IPv6 stay separate family roots.
- Lease miss: apply stream + `ApplyRangeBatch` as today, then rebuild the local tree.
- Lease hit (Redis follower): still GET `range-index` (blob compare is enough; generation key optional). Rebuild if changed.
- Memory cache: no follower hydrate; this process always polls and rebuilds after apply.
- Hydrate at stream start so the first requests are not a Range miss.
- live/none unchanged. Client IP still `pkg/ip.GetRemoteIP`. Do not geolocate. Do not poll LAPI from every pod. Do not MGET `range-index` on the request path.
- Spec `core_plugin_ip_radix-lookup` must stop requiring a per-network Range walk. Spec `core_plugin_decisions_scopes` (ticket wrote `core_plugin_decisionscope`) must say the request path uses the local tree while the blob stays the shared document.

## Affected

- `pkg/crowdsecconnection/connection.go` (`startStream`, `handleStreamCache`, struct, `Close`)
- `pkg/decisionscope/lookup.go`, `pkg/decisionscope/range.go`, tests in `pkg/decisionscope/range_test.go`
- `pkg/iplookup/iplookup.go` (reuse; no payload/delete unless a later change)
- `openspec/specs/core_plugin_ip_radix-lookup/spec.md`
- `openspec/specs/core_plugin_decisions_scopes/spec.md`
- `knowledge/devdocs/core_plugin_decisionscope.md`, `knowledge/devdocs/core_plugin_ip.md`

## Out of scope

- Making `updated` a real lock (`SET NX`).
- Per-request generation-key check.
- Storing CIDRs as many Redis keys.
- Teaching `iplookup` a remediation payload.
- Putting Range membership in `pkg/ip.Checker`.
- Geolocating or changing `GetRemoteIP`.
- Changing live/none LAPI `?ip=` expansion.
- Polling LAPI from every Redis follower.

## Unknowns

- Whether a `range-index-gen` key is needed, or blob-string compare on each follower tick is enough (ticket assumed blob compare for small lists).
- Exact `LookupCachedRemediation` signature once the tree is on the connection (still in `pkg/decisionscope` vs a method on the connection).
- `ext_crowdsec_lapi_stream-cursor` is not on dest; this run may need to commit that finding if later phases cite it as product knowledge.

## Tensions

- `openspec/specs/core_plugin_ip_radix-lookup/spec.md` currently requires Range to stay a per-network walk. This ticket requires that requirement to change.
- `knowledge/devdocs/core_plugin_decisionscope.md` Language Avoid currently forbids a radix tree on the request path. This ticket reverses that Avoid for stream/alone lookup only.
- Today Redis followers stay correct because ServeHTTP MGETs the blob. After this change they stay correct only if the ticker hydrates the local tree on a lease hit. That is a ticker behavior change, not a matching-semantics change.
- `pkg/iplookup` is longest-prefix membership. Range semantics are ban-wins among all containing CIDRs. One LPM tree with a single stored remediation would be wrong; two boolean trees is the ticket’s resolution.
