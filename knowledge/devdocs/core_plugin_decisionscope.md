# Decision scopes

## Language

**Range index**:
One cache blob at key `range-index` whose lines are `cidr=remediation`. Remediation MAY be the letter only or the letter plus U+001F plus a metrics origin. Redis-sharing instances share this document (prefixed by LAPI identity). Stream and alone rebuild in-process membership from it on the ticker and at stream start.
_Avoid_: walking the blob on the request path, one cache key per CIDR, LAPI `?ip=` on the stream path

**Range membership**:
Two boolean CIDR sets (ban, captcha) on the reclaimed LAPI Client plus the stored remediation string per CIDR. Request lookup always asks this pair. Nil or empty (live/none never hydrate) is a Range miss. Ban wins if several containing CIDRs hit; origin comes from the winning CIDR’s stored suffix.
_Avoid_: trusted-IP Checker, one LPM tree with a stored remediation, `sync.Once`, package globals, a Crowdsec-mode flag on lookup

**Header-mapped scope**:
A CrowdSec scope other than Ip/Range whose value comes from a request header named in `decisionScopeHeaders`. Country and AS are normalized; a missing header skips that scope.
_Avoid_: GeoIP inside this plugin, client-set country as the real-stack proof

**decisionScopeHeaders**:
Public Traefik plugin map from CrowdSec scope name to header name. Empty means header scopes are off. Keys `Ip` and `Range` are rejected.
_Avoid_: putting Country on the reclaim key, parsing `RemoteAddr` for country

## Overview

Use `pkg/decisionscope` for cache keys, range-index edits, Range membership from the blob, and the request lookup that merges Ip, Range, and header hits. Ban wins over captcha across those scopes. This package must not geolocate.

## How to use

- Pass `decisionScopeHeaders` from config into the LAPI Client (stream `scopes=` and live `scope`+`value` queries) and into the bouncer (request headers).
- Resolve the client IP with `pkg/ip.GetRemoteIP`. Then `LookupCachedRemediation` with `lapiClient.RangeMembership()`. Pass `req.ipAddr` into Range membership. Matching uses the first letter; origin is for usage-metrics only. Do not put scopes on `clientRequest`.
- Stream Range items: collect the tick, then `ApplyRangeBatch` (one read, one write) with `RemediationWithOrigin`. Hydrate membership from the blob after apply and on a lease hit. Do not GET+SET per Range line.
- Live/none: keep `?ip=` (LAPI expands Range). Add `scope`+`value` when a mapped header is present. Do not hydrate membership. A cache miss still live-looks-up; do not treat that miss as a stream-health decision.
- CAPI (alone) omits `scopes=`. Apply any streamed scope this bouncer is configured to match.

## Pattern snippet

```go
scopes := decisionscope.RequestScopeValues(headers, req)
kind, origin, err := decisionscope.LookupCachedRemediation(cacheClient, req.remoteIP, req.ipAddr, scopes, lapiClient.RangeMembership())
lapiClient.IncDropped(origin, req.ipType, "ban")
```

## Key files

- `pkg/decisionscope/`
- `pkg/configuration/config.go` (`DecisionScopeHeaders`)
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/clientrequest.go`
- `pkg/lapi/client.go`
- `pkg/lapi/client_decisions.go`
- `pkg/lapi/client_stream.go`
- `pkg/lapi/client_live.go`

## Gotchas

- Do not geolocate. Country/AS/username are the mapped header, or they are skipped.
- `Ip` and `Range` are not valid `decisionScopeHeaders` keys.
- A missing mapped header skips that scope; do not fail closed.
- Ban wins across Ip, Range, and header hits. Do not return the first active Ip or Range captcha before considering a Country ban.
- Redis followers skip LAPI on a lease hit. They still GET `range-index` on that tick and rebuild membership; without that hydrate they would miss every Range decision.
- Trust the header the same way you trust `X-Forwarded-For`: only from a trusted hop (CDN or geoenrich in front of this middleware).
- Ip/header/Range-index values MAY be `t`/`c` plus U+001F plus a metrics origin. Bare letters still match. Redis stays one `range-index` key.
- After a cache miss, stream/alone use stream health; live/none call `LiveLookup`. Do not name that split after Range membership.
