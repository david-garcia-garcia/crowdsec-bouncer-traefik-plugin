# Explore
IssueKey: 2026-09-05-performance-ip-range

## Concepts

**Range index** (unchanged): one cache blob at `range-index`, lines `cidr=remediation`. Redis (IdentityHex-prefixed) or the process map is the shared document. `ApplyRangeBatch` stays the writer.

**Range membership** (new, in-process): two `pkg/iplookup.Helper`s on the reclaimed `CrowdsecConnection` — ban CIDRs and captcha CIDRs. Stream/alone request lookup asks this pair, not the blob. Ban tree hit wins; else captcha tree; else miss. Not longest-prefix-wins. Not `pkg/ip.Checker`.

**Lease** (unchanged): cache key `updated`. GET hit skips LAPI. GET miss SET TTL `UpdateIntervalSeconds-1` (min 1) then poll stream. Best-effort, not SET NX. Followers never see `stream.New` / `stream.Deleted`.

**Hydrate**: ticker (and stream start) GET the blob and rebuild Range membership when the raw string changed vs last hydrate. Request path does not GET `range-index`.

Client IP owner is `pkg/ip.GetRemoteIP`. Membership classifies that string (parsed to `net.IP` for `Helper.IsContained`). Do not parse `RemoteAddr` again.

```
  ServeHTTP (stream/alone)
       │
       ├─ GetRemoteIP
       ├─ GetMany(ip, header keys)     // no range-index
       └─ Range membership on conn     // ban Helper, then captcha Helper
              PreferRemediation across Ip / Range / headers

  every pod ticker (handleStreamCache)
       │
       ├─ GET updated hit ──► GET range-index ──► same blob? keep : rebuild
       └─ GET updated miss ─► SET lease, LAPI stream, ApplyRangeBatch, rebuild

  startStream
       └─ GET range-index once, build membership (no extra LAPI poll)
```

## Decisions

- Keep the blob as source of truth. Two boolean Helpers, rebuild from blob, no `DeleteCIDR`, no `range-index-gen`, no iplookup payload.
- `pkg/decisionscope` owns ban-wins membership (`RangeMembership` + `MembershipFromIndex`). `CrowdsecConnection` holds it next to `cacheClient` and swaps a complete pair (atomic pointer). `Close()` drops it with the connection. No `sync.Once`.
- `LookupCachedRemediation` takes the membership (nil or empty = Range miss). `GetMany` omits `RangeIndexKey` in stream/alone.
- Lease-hit path hydrates. Today it returns immediately; after this change followers would otherwise miss every Range decision.
- Invalid blob lines are skipped (`AddCIDR` error), same as `MatchRangeFromIndex` skipping `InNetwork` errors.
- Redis GET failure on hydrate does not wipe a good tree.
- live/none unchanged. Trusted-IP Checker unchanged.
- Spec `core_plugin_ip_radix-lookup` drops “Range stays a per-network walk”. Spec `core_plugin_decisions_scopes` says request path uses in-process membership; blob remains the shared document.
- Usage packets `core_plugin_decisionscope.md` and `core_plugin_ip.md` flip Language Avoid / “leave Range as linear walk” when apply lands (not before).
- LAPI cursor facts: committed `knowledge/research/ext_crowdsec_lapi_stream-cursor/` onto this branch (was missing on dest). Do not poll every pod; Redis followers hydrate from the blob.

Measured this phase: `go test ./pkg/decisionscope ./pkg/iplookup` passed. O(n) walk is `MatchRangeFromIndex` (`pkg/decisionscope/range.go`). Ticket bench numbers were not re-run.

## Open questions

- Q: Who already owns the client address used for Range membership?
  Decision: resolved — `pkg/ip.GetRemoteIP` is the owner. Range membership classifies that string via `net.ParseIP` + `iplookup.Helper.IsContained`. Do not parse `RemoteAddr` in decisionscope or the connection.
  By: explore

- Q: Generation key (`range-index-gen`) or blob-string compare on follower ticks?
  Decision: assumed — compare the raw `range-index` string to the last hydrated blob; skip a `range-index-gen` key. Typical Range cardinality is small. Revisit only if blob GET becomes a problem.
  By: explore

- Q: Where does `LookupCachedRemediation` get the trees?
  Decision: assumed — add a `*RangeMembership` argument owned by `pkg/decisionscope`. Bouncer passes `conn`’s current membership. Do not look up Range inside `pkg/ip.Checker`. Do not add package globals.
  By: explore

- Q: When is the first hydrate relative to serving?
  Decision: assumed — `startStream` GETs `range-index` and builds membership before returning (no extra LAPI call). Redis followers match Range on the first request if the blob already exists. No-Redis: empty until this process’s first stream apply (same as empty blob today). `StreamStartupBlock` still controls whether the first LAPI poll is synchronous.
  By: explore

- Q: How do request-path reads see a rebuild?
  Decision: assumed — build a new Helper pair from the blob, then store it with `atomic.Pointer`. Do not mutate a Helper in place (no delete API). A reader sees the previous complete pair or the new complete pair.
  By: explore

- Q: What if Redis is unreachable during a follower hydrate?
  Decision: assumed — keep the last membership; do not replace it with empty. Same fail posture as today’s cache Get errors on the request path (`RedisUnreachableBlock`).
  By: explore
