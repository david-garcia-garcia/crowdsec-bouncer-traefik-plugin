# Decision scopes

## Language

**Range index**:
One cache blob at key `range-index` whose lines are `cidr=remediation`. Stream and alone match the client IP with CIDR containment. Redis-sharing instances read the same blob (prefixed by connection identity).
_Avoid_: radix tree, one cache key per CIDR, LAPI `?ip=` on the stream path

**Header-mapped scope**:
A CrowdSec scope other than Ip/Range whose value comes from a request header named in `decisionScopeHeaders`. Country and AS are normalized; a missing header skips that scope.
_Avoid_: GeoIP inside this plugin, client-set country as the real-stack proof

**decisionScopeHeaders**:
Public Traefik plugin map from CrowdSec scope name to header name. Empty means header scopes are off. Keys `Ip` and `Range` are rejected.
_Avoid_: putting Country on the reclaim key, parsing `RemoteAddr` for country

## Overview

Use `pkg/decisionscope` for cache keys, range-index edits, and the request lookup that merges Ip, Range, and header hits. Ban wins over captcha across those scopes. This package must not geolocate.

## How to use

- Pass `decisionScopeHeaders` from config into the connection (stream `scopes=` and live `scope`+`value` queries) and into the bouncer (request headers).
- Resolve the client IP with `pkg/ip.GetRemoteIP`. Then `LookupCachedRemediation` in stream/alone/live cache hits.
- Stream Range items: collect the tick, then `ApplyRangeBatch` (one read, one write). Do not GET+SET per Range line.
- Live/none: keep `?ip=` (LAPI expands Range). Add `scope`+`value` when a mapped header is present. Skip `range-index` on none.
- CAPI (alone) omits `scopes=`. Apply any streamed scope this bouncer is configured to match.

## Pattern snippet

```go
scopes := decisionscope.RequestScopeValues(headers, req)
value, err := decisionscope.LookupCachedRemediation(cacheClient, mode, remoteIP, scopes)
```

## Key files

- `pkg/decisionscope/`
- `pkg/configuration/configuration.go` (`DecisionScopeHeaders`)
- `pkg/bouncer/bouncer.go`
- `pkg/crowdsecconnection/connection_decisions.go`

## Gotchas

- Do not geolocate. Country/AS/username are the mapped header, or they are skipped.
- `Ip` and `Range` are not valid `decisionScopeHeaders` keys.
- A missing mapped header skips that scope; do not fail closed.
- Ban wins across Ip, Range, and header hits. Do not return the first active Ip or Range captcha before considering a Country ban.
- Trust the header the same way you trust `X-Forwarded-For`: only from a trusted hop (CDN or geoenrich in front of this middleware).
