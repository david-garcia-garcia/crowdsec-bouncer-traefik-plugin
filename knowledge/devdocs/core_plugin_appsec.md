# AppSec query and challenge relay

## Language

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener (`pkg/appsec`). Owns the HTTP round-trip, JSON parse, host/key/TLS/body limit. Not the LAPI Connection.
_Avoid_: CrowdsecConnection, `AppsecQuery` on LAPI, LAPI captcha

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
- Open with `appsec.Open` (reclaim by AppSec URL+key+TLS). Do not construct the AppSec client inside `lapi.New`.
- `action` allow or empty 200 → `next`. `ban` → `handleBanServeHTTP`. Any other non-allow action (challenge, AppSec captcha HTML) → relay. Empty `challenge` body → ban. AppSec `captcha` is not `pkg/captcha`.
- AppSec HTTP 500, unreachable, and unreadable body use per-router `crowdsecAppsecFailureAction` (`passthrough` | `ban` | `captcha`), not the three removed block bools. `captcha` here is `pkg/captcha`, not AppSec JSON `action: captcha`.
- Route `PathPrefix(/crowdsec-internal/challenge)` through the same middleware; service backend is the AppSec listener.
- Copy request `Cookie` through to AppSec (already copied with other headers). Do not parse `__crowdsec_challenge` in this plugin.

## Pattern snippet

```go
decision, err := b.appsecClient.Query(req.remoteIP, req.Request, pol)
```

## Key files

- `pkg/appsec/`
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/clientrequest.go`

## Gotchas

- Challenge always arrives as AppSec listener 403 plus JSON `action: challenge`. Browser status is `http_status` (often 200, sometimes 307).
- Missing `http_status` is 200. Values outside 100–999 use `remediationStatusCode`.
- Do not send `/crowdsec-internal/challenge/*` to origin.
- `Query` `captcha` failure action is `ErrFailureCaptcha` → `pkg/captcha`. Do not treat that error as AppSec JSON `action: captcha`.
- Empty `crowdsecAppsecKey` still falls back to `crowdsecLapiKey` in `appsec.Prepare`. Call `lapi.Prepare` first.
