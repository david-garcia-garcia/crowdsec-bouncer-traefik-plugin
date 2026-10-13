# Delivery

## Motivation
Stream ingest stored a LAPI decision whose type was neither `ban` nor `captcha` (for example `challenge`) as an empty cache payload. Cache Get treats empty as a miss. A healthy stream then allowed the IP.

Live and none returned that empty payload on the first query (already remediates as a ban) and cached a miss, so the next Get repeated the LAPI call. CrowdSec's challenge protocol and lua-cs-bouncer fail closed to ban for unsupported types. Leaving stream allow is a wrong public contract for those IPs.

Priority: P1 — production serves a wrong public contract today

## Implementation
Both ingest switches call `lapiDecisionRemediation`, which maps `ban` and `captcha` to their cache payloads and maps every other type to `cache.BannedValue` after the existing `handleStreamCache:unknownType` Info log. Empty lists and JSON `null` stay `cache.NoBannedValue`. Tests assert stream Get and live cache for `challenge`/`allow`, and an empty live list still allowed.

CI Yaegi checkout is the go.mod module path (`github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`) with vendor packages copied onto GOPATH/src, so this fork can load `pkg/cache`. Dest `main` already failed that check.

## What this changes
**Operators.** A `challenge` or other unknown LAPI/blocklist decision now bans the IP in stream, live, and none.
**Admin users.** None.
**Developers.** Ingest unknown types store `cache.BannedValue`; Yaegi CI checkouts at the Go module path.
**End users.** An IP with an unknown LAPI type is banned instead of allowed in stream mode.
