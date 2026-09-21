# Explore
IssueKey: 2026-09-18-ip-cache-key-canonicalization

## Concepts

- **The cache is string-keyed, CrowdSec is not.** CrowdSec stores a decision value verbatim and
  matches `?ip=` numerically (measured on v1.8.0 before this ticket). So the plugin is the only place
  where two spellings of one address become two different things, and the fix has to live here.
- **Three write sites, one read site.** `storeStreamDecision` and `deleteStreamDecision` key on
  `IPCacheKey(item.Value)`; `handleNoStreamCache` keys the live memo on the raw `remoteIP`;
  `LookupCachedRemediation` reads with the raw `remoteIP`. `IPCacheKey` only canonicalized host
  prefixes, so the store side was verbatim for bare values and the read side was verbatim always —
  symmetric by accident, and only for the spellings that happen to round-trip.
- **Live mode is the trap.** Its memo is written by the LAPI client and read by the request path.
  Canonicalizing the read side alone makes that pair asymmetric, which is a permanent miss rather
  than an occasional one.
- **The range index is shared.** `range-index` is one blob every bouncer on that cache reads and
  rewrites. `readRangeIndex` returning `""` for an unreachable read means a poll rebuilds the shared
  document from nothing.
- **Reads and writes do not use the same Redis connection.** `cache.redisCache.get` uses
  `nextReader()` (round-robin over `lapiRedisReadHosts`), while `acquire` and `set` use `writer`.
  That is what makes the range-index defect reachable with a healthy writer.

## Decisions

- One canonicalization rule owned by `IPCacheKey`, with `IPLookupCacheKey` as the request-path entry
  point so the request does not re-parse an address `pkg/ip` already parsed. Their agreement is
  asserted by a test, not by review.
- Write side and read side move in the same commit, including the live-mode memo that PR #34 left
  out. The proof is a LAPI-query count, not a passing test suite.
- The LAPI query string keeps the raw `remoteIP`: LAPI is spelling-agnostic, so rewriting the wire
  buys nothing.
- A range apply that cannot read the index fails the poll instead of skipping the write quietly.
- PR #34's second half is kept, not dropped. It is neither unreachable nor cosmetic: see the
  read-replica path above and the measured truncation of the shared blob.

## Open questions

- Q: Should an aborted range apply fail the whole stream poll, or only skip the write and let the
  tick be reported as clean (what PR #34 did)?
  Decision: resolved — fail the poll. Skipping quietly preserves the index but loses this tick's
  Range delta for good, because later polls run with `startup=false` and never carry it again.
  Failing the poll releases the lease for an immediate retry and leaves `isCrowdsecStreamStartup`
  set, so the retry asks for the full set. Cost: with the default `lapiUpdateMaxFailure: 0` a read-replica
  blip now marks the stream unhealthy and cache misses take `bouncerLapiFailureAction`. That is the
  same posture the surrounding code already takes for a failed stream fetch. Called out on the card.
  By: explore

- Q: Do any cache entries need migrating to the new spelling?
  Decision: resolved — no. Ip entries carry the decision TTL and expire on their own, IPv4 spellings
  were already identical, and the only entries whose key changes are ones that could not be found
  anyway. `deleteStreamDecision` still deletes the verbatim value as legacy cleanup.
  By: explore

- Q: Are `AddRange` / `RemoveRange` still production code?
  Decision: resolved — no, both are test-only. They keep swallowing the new error with `_ =` rather
  than growing this diff; recorded on `issues.md` as a note.
  By: explore
