See proposal.md — Why.

## Approach

### 1. One canonicalization rule, two entry points

`IPCacheKey(value)` stays the owner of the rule. It gains the bare-address branch it was missing:
`net.ParseCIDR` first (host prefix collapses to the address, a real network stays verbatim), then
`net.ParseIP`, then verbatim. `net.IP.String()` is the canonical form, and it is the same
normalization CrowdSec applies numerically when it answers `?ip=`, including collapsing an
IPv4-mapped address to its dotted form.

`IPLookupCacheKey(remoteIP, ipAddr)` is the request-path entry point. It is not a second rule: it
returns `ipAddr.String()` when the address parsed and the trimmed raw string when it did not, which
is what `IPCacheKey(remoteIP)` would return for the same input. It exists so the request path does
not parse a string `pkg/ip.GetRemoteIP` already parsed for it — `core_plugin_decisions_scopes` states
that the client IP has one owner and the request path must not parse it twice. That the two agree is
an invariant, so it is asserted by a test over every spelling in play rather than left to review.

The nil-`ipAddr` fallback is reachable: with `forwardedHeadersInsecure` the header value is taken
whole and may not be an address. The bouncer already bans that request on `tech_trustipfail` before
lookup, so the fallback is a belt-and-braces path, and keeping it verbatim matches what the store
side does with an unparseable decision value.

### 2. The write side moves in the same commit

This is the whole reason the two halves of deliverable 1 cannot be split. Three write sites key on an
address, and they have to move together with the read side:

| Site | DestBranch key | After |
|------|----------------|-------|
| `storeStreamDecision` | `IPCacheKey(item.Value)` | same call, now canonical for bare values |
| `deleteStreamDecision` | `IPCacheKey(item.Value)` plus the verbatim `item.Value` | same; the verbatim delete stays as legacy cleanup |
| `handleNoStreamCache` | the raw `remoteIP` | `IPCacheKey(remoteIP)` |

The live-mode memo is the trap. It is written by the LAPI client and read back by
`LookupCachedRemediation`, so canonicalizing the read side alone turns every live request whose
header spelling is not already canonical into a permanent memo miss and a fresh LAPI query per
request — strictly worse than the defect being fixed. Measured: 5 requests from one address needed 5
LAPI queries under that shape, against 1 on DestBranch and 1 after this change.

The LAPI query itself keeps the raw `remoteIP`. LAPI matches numerically, so rewriting the query
would change the wire for no gain.

### 3. Range apply fails the poll, it does not quietly skip

`readRangeIndex` separates `CacheMiss` (an index nobody has written yet — apply normally, this is the
first Range decision) from any other failure (the cache did not answer — the caller cannot know what
is in there).

`ApplyRangeBatch` returns the error and writes nothing. `fetchAndApplyStreamDecisions` wraps and
returns it rather than logging and continuing, because a tick that dropped its Range delta is a tick
that did not finish, which is exactly what the surrounding code already means by a failed poll:
`handleStreamCache` releases the lease so the next tick retries immediately, and the failure leaves
`isCrowdsecStreamStartup` set so `streamQuery` asks for `startup=true` and the delta comes back. The
alternative — log at `Debug` and report the poll as clean — preserves the index but loses this tick's
Range bans for good, because later polls run with `startup=false` and never carry them again.

`AddRange` and `RemoveRange` discard the error with `_ =`. They are test-only convenience wrappers
with no production caller; that is recorded on `devstate/issues.md` rather than grown into this diff.

## Alternatives considered

- **Have the request path call `IPCacheKey(remoteIP)` and drop `IPLookupCacheKey`.** One function
  instead of two, at the cost of re-parsing, per request, the address the request already parsed.
  Rejected on the ownership rule above; the equivalence test keeps the two honest.
- **Migrate existing cache entries to the new spelling.** Rejected: Ip entries carry a decision TTL
  and expire on their own, and the only entries affected are ones that were unreachable anyway.
- **Canonicalize inside `pkg/cache`.** Rejected: the cache keys header scopes and `range-index` too,
  and neither is an address. Address normalization belongs to the package that knows a key is an
  address.
- **PR #34's `IPLookupCacheKey`, which prefers `IPCacheKey(remoteIP)` when it differs from the raw
  string and otherwise falls back to `ipAddr`.** Rejected: that branch only exists because
  `IPCacheKey` could not canonicalize bare addresses. Fixing `IPCacheKey` deletes the branch.
