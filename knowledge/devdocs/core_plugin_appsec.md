# AppSec query and challenge relay

## Language

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener (`pkg/appsec`). Owns JSON parse, host/path/body limit, and replaceable HTTP+auth (`transport` on `atomic.Value`). Not the LAPI Client.
_Avoid_: CrowdsecConnection, `AppsecQuery` on LAPI, LAPI captcha, `atomic.Pointer[T]`

**Structured AppSec response**:
JSON CrowdSec 1.8 AppSec returns to the bouncer (`action`, `http_status`, `user_body_content`, `user_cookies`, `user_headers`). Listener HTTP 403 carries a remediation envelope; listener 200 is allow.
_Avoid_: LAPI captcha, ban template HTML, `RemoteAddr`

**Challenge**:
AppSec `action` `challenge`. The bouncer writes that envelope to the browser. `/crowdsec-internal/challenge/*` must use the same middleware so the callback is not sent to origin.
_Avoid_: CrowdSec LAPI captcha remediation

## Overview

`appsec.Client.Query` owns the AppSec HTTP round-trip and JSON parse. `Bouncer` owns writing the client response or the operator ban template. Client IP is `pkg/ip.GetRemoteIP` only; AppSec handlers take `clientRequest` still named `req`.

## How to use

- Enable with existing `crowdsecAppsecEnabled`. Do not add a bot-detection plugin key.
- Open with `appsec.Open` (reclaim by AppSec URL+key+body limit). `Open` calls `AdoptTransport` so last `New` wins TLS/timeout. Do not construct the AppSec client inside `lapi.New`. Do not use `atomic.Pointer[T]`.
- `action` allow or empty 200 → `next`. `ban` → `handleBanServeHTTP`. Any other non-allow action (challenge, AppSec captcha HTML) → relay. Empty `challenge` body → ban. Empty `captcha` body still relays `http_status` (not the operator ban page). AppSec `captcha` is not `pkg/captcha`.
- AppSec HTTP 500, unreachable (transport failure or listener HTTP 502/503/504), AppSec response-body io errors, and an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH use per-router `crowdsecAppsecFailureAction` (`passthrough` | `ban` | `captcha`), not the three removed block bools. `captcha` here is `pkg/captcha`, not AppSec JSON `action: captcha`. A response-body io error keeps `appsecQuery:readBody`. Oversized AppSec bodies do not use this action.
- `crowdsecAppsecBodyLimit` `0` is unlimited: skip `io.LimitReader` and `io.ReadAll` the readable client body. A positive limit still caps the copy. Omitted default stays 10485760.
- After the forwarded bytes exist, omit client `Content-Length` and `Transfer-Encoding`; set `Request.ContentLength` and the header from those bytes. Reuse the `ip` argument on `X-Crowdsec-Appsec-Ip`.
- Drain and close every non-nil AppSec `Do` response before return, including 502/503/504. Transport errors have no body.
- Route `PathPrefix(/crowdsec-internal/challenge)` through the same middleware; service backend is the AppSec listener.
- Copy request `Cookie` through to AppSec (already copied with other headers). Do not parse `__crowdsec_challenge` in this plugin.

## Pattern snippet

```go
decision, err := b.appsecClient.Query(req.remoteIP, req.Request, pol)
```

## Key files

- `pkg/appsec/`
- `pkg/appsec/client_http.go`
- `pkg/appsec/session.go`
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/clientrequest.go`

## Gotchas

- Challenge always arrives as AppSec listener 403 plus JSON `action: challenge`. Browser status is `http_status` (often 200, sometimes 307).
- Missing `http_status` is 200. Values outside 100–999 use `remediationStatusCode`.
- Do not send `/crowdsec-internal/challenge/*` to origin.
- `Query` `captcha` failure action is `ErrFailureCaptcha` → `pkg/captcha`. Do not treat that error as AppSec JSON `action: captcha`.
- Empty `crowdsecAppsecKey` still falls back to `crowdsecLapiKey` in `appsec.Prepare`. Call `lapi.Prepare` first.
- HTTP 502, 503, and 504 from the AppSec listener are unreachable (same `crowdsecAppsecFailureAction` as a transport failure), not a generic non-200 ban. Drain those bodies so keep-alive can reuse the slot.
- DELETE is not an unreadable-body drop. Do not gate the readable-body copy on `isMethodWithBody`.
- Do not pass `0` into `io.LimitReader` (`N <= 0` is immediate EOF).
- Do not put AppSec TLS or `HTTPTimeoutSeconds` in the AppSec reclaim key. Last `New` `AdoptTransport`s those knobs. Concurrent adopt last-writes and idle-closes the replaced `*http.Client`.
