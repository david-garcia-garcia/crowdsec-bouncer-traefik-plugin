# Decision scopes

## Language

**Range index**:
One cache blob at key `range-index` whose lines are `cidr=remediation`. Redis-sharing instances share this document (prefixed by connection identity). Stream and alone rebuild in-process membership from it on the ticker and at stream start.
_Avoid_: walking the blob on the request path, one cache key per CIDR, LAPI `?ip=` on the stream path

**Range membership**:
Two boolean CIDR sets (ban, captcha) on the reclaimed CrowdsecConnection. Stream/alone request lookup asks this pair. Ban wins if several containing CIDRs hit.
_Avoid_: trusted-IP Checker, one LPM tree with a stored remediation, `sync.Once`, package globals

**Header-mapped scope**:
A CrowdSec scope other than Ip/Range whose value comes from a request header named in `decisionScopeHeaders`. Country and AS are normalized; a missing header skips that scope.
_Avoid_: GeoIP inside this plugin, client-set country as the real-stack proof

**decisionScopeHeaders**:
Public Traefik plugin map from CrowdSec scope name to header name. Empty means header scopes are off. Keys `Ip` and `Range` are rejected.
_Avoid_: putting Country on the reclaim key, parsing `RemoteAddr` for country

## Overview

Use `pkg/decisionscope` for cache keys, range-index edits, Range membership from the blob, and the request lookup that merges Ip, Range, and header hits. Ban, captcha, and none payloads are `BannedValue` (`t`), `CaptchaValue` (`c`), and `NoBannedValue` (`f`) on that package. Ban wins over captcha across those scopes. This package must not geolocate.

## How to use

- Pass `decisionScopeHeaders` from config into the connection (stream `scopes=` and live `scope`+`value` queries) and into the bouncer (request headers).
- Resolve the client IP with `pkg/ip.GetRemoteIP`. Then `LookupCachedRemediation` with `conn.RangeMembership()` in stream/alone/live cache hits.
- Stream Range items: collect the tick, then `ApplyRangeBatch` (one read, one write). Hydrate membership from the blob after apply and on a lease hit. Do not GET+SET per Range line.
- Live/none: keep `?ip=` (LAPI expands Range). Add `scope`+`value` when a mapped header is present. Skip `range-index` and membership on none.
- CAPI (alone) omits `scopes=`. Apply any streamed scope this bouncer is configured to match.

## Pattern snippet

```go
scopes := decisionscope.RequestScopeValues(headers, req)
value, err := decisionscope.LookupCachedRemediation(cacheClient, mode, remoteIP, scopes, conn.RangeMembership())
```

## Key files

- `pkg/decisionscope/`
- `pkg/configuration/configuration.go` (`DecisionScopeHeaders`)
- `pkg/bouncer/bouncer.go`
- `pkg/crowdsecconnection/connection.go`
- `pkg/crowdsecconnection/connection_decisions.go`

## Gotchas

- Do not geolocate. Country/AS/username are the mapped header, or they are skipped.
- `Ip` and `Range` are not valid `decisionScopeHeaders` keys.
- A missing mapped header skips that scope; do not fail closed.
- Ban wins across Ip, Range, and header hits. Do not return the first active Ip or Range captcha before considering a Country ban.
- Redis followers skip LAPI on a lease hit. They still GET `range-index` on that tick and rebuild membership; without that hydrate they would miss every Range decision.
- Trust the header the same way you trust `X-Forwarded-For`: only from a trusted hop (CDN or geoenrich in front of this middleware).
