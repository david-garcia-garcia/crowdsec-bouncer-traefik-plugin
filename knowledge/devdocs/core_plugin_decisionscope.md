# Decision scopes

## Language

**Range index**:
One cache blob at key `range-index` whose lines are `cidr=remediation`. Remediation MAY be the letter only or the letter plus U+001F plus a metrics origin. Redis-sharing instances share this document (prefixed by LAPI identity). Stream and alone rebuild in-process membership from it on the ticker and at stream start.
_Avoid_: walking the blob on the request path, one cache key per CIDR, LAPI `?ip=` on the stream path

**Range membership**:
Two boolean CIDR sets (ban, captcha) on the reclaimed LAPI Client plus the stored remediation string per CIDR. Request lookup always asks this pair. Nil or empty (live/none never hydrate) is a Range miss. Ban wins if several containing CIDRs hit; origin comes from the winning CIDR’s stored suffix.
_Avoid_: trusted-IP Checker, one LPM tree with a stored remediation, `sync.Once`, package globals, a Crowdsec-mode flag on lookup

**Ip cache key**:
The one canonical spelling an Ip-scoped decision is filed under, `net.IP.String()` of the address. `IPCacheKey` derives it from a decision value (host prefix, bare address, or verbatim when neither); `IPLookupCacheKey` derives the same key on the request path from the `net.IP` `pkg/ip.GetRemoteIP` already produced. CrowdSec stores decision values verbatim, so both entry points exist to make one address one slot.
_Avoid_: keying on the raw header text, canonicalizing one side without the other, re-parsing `remoteIP` in the request path, pushing a Country or AS value through address parsing

**Header-mapped scope**:
A CrowdSec scope other than Ip/Range whose value comes from a request header named in `decisionScopeHeaders`. Country and AS are normalized; a missing header skips that scope.
_Avoid_: GeoIP inside this plugin, client-set country as the real-stack proof

**decisionScopeHeaders**:
Public Traefik plugin map from CrowdSec scope name to header name. Empty means header scopes are off. Keys `Ip` and `Range` are rejected.
_Avoid_: putting Country on the reclaim key, parsing `RemoteAddr` for country

## Overview

Use `pkg/decisionscope` for cache keys, range-index edits, Range membership from the blob, and the request lookup that merges Ip, Range, and header hits. Ban, captcha, and none payloads are `BannedValue` (`t`), `CaptchaValue` (`c`), and `NoBannedValue` (`f`) on that package. Ban wins over captcha across those scopes. This package must not geolocate.

## How to use

- Pass `decisionScopeHeaders` from config into the bouncer (request headers). Stream `scopes=` and the stream store filter are the live-router union (`core_plugin_lapi_scope-union.md`). Live/none still pass scopes per `LiveLookup`.
- Resolve the client IP with `pkg/ip.GetRemoteIP`. Then `LookupCachedRemediation` with `lapiClient.RangeMembership()`. Pass `req.ipAddr` into Range membership; it is also what `IPLookupCacheKey` derives the Ip slot from. Matching uses the first letter; origin is for usage-metrics only. Do not put scopes on `clientRequest`.
- Writing an Ip slot from anywhere (stream store, stream delete, live memo) goes through `IPCacheKey`. Changing one side of that pair on its own is a permanent cache miss, not a partial fix.
- Stream Range items: collect the tick, then `ApplyRangeBatch` (one read, one write) with `RemediationWithOrigin`. It returns an error when it could not read the shared blob; propagate it so the poll counts as failed. Hydrate membership from the blob after apply and on a lease hit. Do not GET+SET per Range line.
- Live/none: keep `?ip=` (LAPI expands Range). Add `scope`+`value` when a mapped header is present. Do not hydrate membership. The live client-address cache key stores the `?ip=` result only; header remediations stay on `HeaderScopeKey`. A cache miss still live-looks-up; do not treat that miss as a stream-health decision.
- CAPI (alone) omits `scopes=`. Apply any streamed scope this bouncer is configured to match.

## Pattern snippet

```go
scopes := decisionscope.RequestScopeValues(headers, req)
kind, origin, err := decisionscope.LookupCachedRemediation(cacheClient, req.remoteIP, req.ipAddr, scopes, lapiClient.RangeMembership())
lapiClient.IncDropped(origin, req.ipType, "ban")
```

## Key files

- `pkg/decisionscope/`
- `pkg/configuration/configuration.go` (`DecisionScopeHeaders`)
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
- CrowdSec does not canonicalize decision values — measured on v1.8.0, the stream hands back `2001:DB8::2` and `::ffff:192.0.2.4` exactly as submitted. LAPI `?ip=` does match numerically, so the spelling problem is ours alone and needs no LAPI workaround.
- `Get` runs on a round-robin `redisCacheReadHosts` replica while `Acquire` and `Set` run on the writer. A read path can fail on a completely healthy writer; that is how the range-index apply reached its unread-base defect without any timing window.
