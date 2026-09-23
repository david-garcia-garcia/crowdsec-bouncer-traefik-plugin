# Decision scopes

## Language

**Range index**:
One store blob at key `range-index` whose lines are `cidr=kind` plus optional origin on the next newline (`KindOriginString`). Redis-sharing instances share this document (prefixed by SessionHex). Stream and alone rebuild in-process membership from it on the ticker and at stream start.
_Avoid_: walking the blob on the request path, one store key per CIDR, LAPI `?ip=` on the stream path, intern ids in the blob, leftover U+001F

**KindOriginString**:
A string of kind letter, then newline, then a metrics origin name. Redis slots and the range-index blob keep this spelling. Letter-only is still a hit. Helpers live in `pkg/decisionstore`.
_Avoid_: leftover, `RemediationWithOrigin`, U+001F

**Range membership**:
Two utilities Helpers (ban, captcha) on the reclaimed DecisionStore. Each Range `AddCIDR` MAY pass the blob remediation string (letter, optional newline origin) as metadata. Request lookup always asks this pair. Nil or empty (live/none never hydrate) is a Range miss. Ban wins if several containing CIDRs hit; origin comes from the winning CIDR’s `KindOriginString` suffix.
_Avoid_: trusted-IP Checker, one LPM tree, `sync.Once`, package globals, a Crowdsec-mode flag on lookup, re-parsing `storedByCIDR` on a Range hit

**Ip cache key**:
The one canonical spelling an Ip-scoped decision is filed under, `net.IP.String()` of the address. `IPCacheKey` derives it from a LAPI decision value (host prefix, bare address, or verbatim when neither). After a successful parse, `clientRequest.remoteIP` is that same string and is the request-path key. CrowdSec stores decision values verbatim, so the store path still canonicalizes text; the request path must not re-parse.
_Avoid_: keying on the raw header text, a second request-path key helper, re-parsing `remoteIP` in lookup or the live memo, pushing a Country or AS value through address parsing

**Header-mapped scope**:
A CrowdSec scope other than Ip/Range whose value comes from a request header named in `bouncerDecisionScopeHeaders`. Country and AS are normalized; a missing header skips that scope.
_Avoid_: GeoIP inside this plugin, client-set country as the real-stack proof

**BouncerDecisionScopeHeaders**:
Public Traefik plugin map from CrowdSec scope name to header name. Empty means header scopes are off. Keys `Ip` and `Range` are rejected.
_Avoid_: putting Country on the reclaim key, parsing `RemoteAddr` for country, decisionScopeHeaders

## Overview

Use `pkg/decisionscope` for letters, PreferRemediation, RequestScopeValues, StreamScopeList, and Normalize*. Range-index edits, membership, and request lookup that merges Ip, Range, and header hits live on `pkg/decisionstore`. Ban, captcha, and none payloads are `BannedValue` (`t`), `CaptchaValue` (`c`), and `NoBannedValue` (`f`) on decisionscope. Ban wins over captcha across those scopes. This package must not geolocate.

## How to use

- Pass `bouncerDecisionScopeHeaders` from config into the bouncer (request headers). Stream `scopes=` and the stream store filter are the live-router union (`core_plugin_lapi_scope-union.md`). Live/none still pass scopes per `LiveLookup`.
- Resolve the client IP with `pkg/ip.GetRemoteIP`. After a successful parse, set `req.remoteIP = req.ipAddr.String()` before lookup, live memo, or captcha bind. Then `lapiClient.LookupRemediation`. Pass `req.remoteIP` as the Ip key and `req.ipAddr` only into Range membership. Matching uses the first letter; origin is for usage-metrics only. Do not put scopes on `clientRequest`.
- Writing an Ip slot from a LAPI decision value (stream store, stream delete) goes through `IPCacheKey`. The live memo writes `Set(remoteIP)` using the already-canonical request string. Changing one side of that pair on its own is a permanent cache miss, not a partial fix.
- Stream Range items: collect the tick, then Store `ApplyRangeBatch` (one read, one write) with `KindOriginString`. Removals run before upserts so a same-window CIDR replacement stays (`core_plugin_lapi_stream-apply.md`). It returns an error when it could not read the shared blob; propagate it so the poll counts as failed. Hydrate membership from the blob after apply and at stream start. Do not GET+SET per Range line.
- Live/none: keep `?ip=` (LAPI expands Range). Add `scope`+`value` when a mapped header is present. Do not hydrate membership. The live client-address cache key stores the `?ip=` result only; header remediations stay on `HeaderScopeKey`. A cache miss still live-looks-up; do not treat that miss as a stream-health decision.
- CAPI (alone) omits `scopes=`. Apply any streamed scope this bouncer is configured to match.

## Pattern snippet

```go
scopes := decisionscope.RequestScopeValues(headers, req)
req.remoteIP = req.ipAddr.String()
kind, origin, originID, err := lapiClient.LookupRemediation(req.remoteIP, req.ipAddr, scopes)
if origin == "" {
	origin = lapiClient.OriginName(originID)
}
lapiClient.IncDropped(origin, req.ipType, "ban")
```

## Key files

- `pkg/decisionscope/`
- `pkg/configuration/configuration.go` (`BouncerDecisionScopeHeaders`)
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/clientrequest.go`
- `pkg/decisionstore/`
- `pkg/lapi/client.go`
- `pkg/lapi/client_decisions.go`
- `pkg/lapi/client_stream.go`
- `pkg/lapi/client_live.go`

## Gotchas

- Do not geolocate. Country/AS/username are the mapped header, or they are skipped.
- `Ip` and `Range` are not valid `bouncerDecisionScopeHeaders` keys.
- A missing mapped header skips that scope; do not fail closed.
- Ban wins across Ip, Range, and header hits. Do not return the first active Ip or Range captcha before considering a Country ban.
- Shared Redis instances GET `range-index` through the Store and rebuild membership; without that hydrate they would miss every Range decision. There is no stream lease.
- Trust the header the same way you trust `X-Forwarded-For`: only from a trusted hop (CDN or geoenrich in front of this middleware).
- Redis Ip/header/Range-index values MAY be `t`/`c` plus newline plus a metrics origin (`KindOriginString`). Bare letters still match. Redis stays one `range-index` key. Packed intern ids are uint32 words on memory Ip/header slots only.
- Request lookup is Store `LookupRemediation`. Resolve `OriginName` only on drop.
- After a cache miss, stream/alone use stream health; live/none call `LiveLookup`. Do not name that split after Range membership.
- CrowdSec does not canonicalize decision values — measured on v1.8.0, the stream hands back `2001:DB8::2` and `::ffff:192.0.2.4` exactly as submitted. LAPI `?ip=` does match numerically, so the spelling problem is ours alone and needs no LAPI workaround.
- Redis Get/MGET run on a round-robin `lapiRedisReadHosts` replica while SET/DEL run on the writer. A read path can fail on a completely healthy writer; a replica miss must not retry the writer.
- Range-index upsert and remove match a line by same network (masked IP + prefix), not raw CIDR text. Persist the incoming spelling. `AddRange(10.1.2.0/8)` then `RemoveRange(10.0.0.0/8)` drops that line. Unparseable text still matches only when the strings are identical.
- A parseable Range host is stored as `/32` or `/128` (`pkg/ip.HostCIDR`) on upsert and remove so write and delete pair. Membership is ParseCIDR-only; a bare `192.0.2.1=t` line is skipped. Unparseable lines are still skipped.
