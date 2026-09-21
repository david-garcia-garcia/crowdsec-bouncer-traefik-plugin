# Code review — Security
Pin: origin/master...HEAD

## Findings

- [accepted] **Behavior change, fail-closed direction.** A stream poll whose Range apply cannot read
  `range-index` is now a failed poll. With the default `lapiUpdateMaxFailure: 0` that marks the stream
  unhealthy, and stream/alone cache misses then take `bouncerLapiFailureAction`, whose default is
  `ban`. So a dead `lapiRedisReadHosts` replica can turn into bans on cache-miss traffic.
  Argument: the alternative loses enforcement instead. Logging at `Debug` and calling the tick clean
  keeps the index intact but drops this tick's Range bans permanently, because later polls run with
  `startup=false` and never carry them again. The surrounding code already treats a poll that did not
  finish exactly this way (`handleStreamCache` releases the lease on any post-`Acquire` failure), and
  `passthrough` remains the operator's way back. Called out on the delivery card as a decision the
  owner should see.

- [resolved] **Canonicalization cannot widen a match.** `net.IP.String()` is a total function on a
  parsed address and collapses only spellings of the *same* address; it never maps two different
  addresses onto one key. The IPv4-mapped collapse (`::ffff:192.0.2.4` → `192.0.2.4`) matches what
  CrowdSec itself does numerically on `?ip=`, measured before this ticket.

- [resolved] **Non-IP scopes are untouched.** Country and AS still go through
  `NormalizeHeaderScopeValue` and `HeaderScopeKey`; nothing pushes a header-scope value through
  address parsing. Asserted by `TestStoreStreamDecision_HeaderScopesAreNotAddresses`.

- [resolved] **The unparseable client address still fails closed.** `IPLookupCacheKey` falls back to
  the verbatim string when `ipAddr` is nil, which is the same key the store side would produce. The
  bouncer bans that request on `tech_trustipfail` before lookup anyway, so the fallback never decides
  a live request today.
