# Explore

## Concepts

Units this change would touch:

- `handleStreamCache` (`bouncer.go`) — stream New ingest: maps LAPI `type` to cache payload and `Set`s the IP.
- `handleNoStreamCache` (`bouncer.go`) — live and none query ingest: maps LAPI `type` to a returned payload and, in live, `Set`s it.
- `ServeHTTP` (`bouncer.go`) — stream: cache hit remediates anything other than `cache.NoBannedValue`; cache miss with a healthy stream allows. Live/none: remediates anything other than `cache.NoBannedValue`.
- `localCache.get` / `redisCache.get` (`pkg/cache/cache.go`) — empty stored string is `CacheMiss`. Not a seam to change: empty means miss for every caller.

How they connect:

```
LAPI stream New  --> handleStreamCache switch --> cache.Set(ip, value)
ServeHTTP stream --> cache.Get(ip) --> miss? allow : remediate(value)

LAPI live/none   --> handleNoStreamCache switch --> return value (+ live Set)
ServeHTTP live   --> cache.Get or handleNoStreamCache --> value == NoBannedValue? allow : remediate
```

Call sites that matter: **2** type-to-payload switches (`handleStreamCache`, `handleNoStreamCache`). Roots searched: `bouncer.go`. `cache.Get` empty-as-miss has 2 implementations (`localCache.get`, `redisCache.get`); this change does not migrate them.

Reproduce: throwaway `go test -v -count=1 -run TestExploreRepro` in the worktree (file deleted after).

- Stream `type=challenge`: log `handleStreamCache:unknownType challenge` at Info; `cache.Get` = `""` err=`cache:miss` (not `cache.BannedValue` `"t"`).
- Live `type=challenge`: return value=`""` err=`handleNoStreamCache:banned`; live `Set` of empty then `cache.Get` is also miss. ServeHTTP would still ban the first query because `"" != cache.NoBannedValue`.

Outside facts used: not in dest tree (`knowledge/` absent). CrowdSec challenge protocol: a LAPI/blocklist `challenge` has nothing to render and must fail closed to ban (https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md). lua-cs-bouncer `FALLBACK_REMEDIATION=ban` for unknown remediations (https://docs.crowdsec.net/u/bouncers/nginx/, https://github.com/crowdsecurity/lua-cs-bouncer/blob/main/config_example.conf). CrowdSec maintainers: LAPI `allow` is not a supported remediation (https://github.com/crowdsecurity/cs-nginx-bouncer/issues/100). Upstream point 1: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 — two `value = cache.BannedValue` defaults plus a stream cache test. Dest gap: those assignments are missing; this fork did not copy that patch.

No `knowledge/devdocs` on dest. Do not bootstrap a usage catalog for this ingest default.

## Decisions

- Chosen: in both ingest switches, `default` sets `value = cache.BannedValue` after the existing `handleStreamCache:unknownType` log. Stream Get then hits a ban; live returns and caches a ban. Empty list / JSON `null` stay `NoBannedValue`.
- Chosen: keep dest log level Info at the existing message. Ticket's Debug names a mapper that is not on dest.
- Chosen: do not change `cache.Get` empty-as-miss, and do not add `RemediationValue` (not on dest).
- Chosen: regression tests on dest `bouncer_test.go` that fail if stream Get or live return is not `cache.BannedValue` for `challenge` (and another unknown such as `allow`). Cover empty list still allowed.
- Rejected: copying upstream PR 403 wholesale (points 2–6 out of scope).
- Rejected: treating live empty return as enough (ticket: stored and applied; live cache of empty is a miss).
- Live contract: no live contract (`openspec/` absent on dest). Do not bootstrap a catalog.

## Open questions

- Q: Should unknown LAPI types be stored as `cache.BannedValue` at both ingest switches, including live which already remediates an empty return as a ban?
  Rank: bounded asked — 2 existing switches in `bouncer.go` (roots searched: `bouncer.go`); Desired: stored and applied as a ban in stream and live
  Decision: assumed — yes; set `cache.BannedValue` in both `default` branches so stream Get and live cache hits stay bans.
  By: explore

- Q: Keep dest Info at `handleStreamCache:unknownType`, or change it to Debug as the ticket's "today" wording?
  Rank: additive asked — Desired: log at the existing log site
  Decision: assumed — keep Info; dest's existing site is Info, not Debug.
  By: explore

- Q: Bootstrap an OpenSpec catalog on dest, which has none?
  Rank: additive incidental — requirement does not name a spec; dest has no `openspec/`
  Decision: assumed — no live contract; propose journals `none — no live contract`; do not bootstrap a catalog.
  By: explore
