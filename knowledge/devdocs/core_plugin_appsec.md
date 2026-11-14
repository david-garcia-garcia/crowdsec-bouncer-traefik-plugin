# AppSec query and challenge relay

## Language

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener (`pkg/appsec`). Keyed by middleware name plus host, path, resolved key, effective body limit, TLS, `appsecHttpTimeoutSeconds`, and `appsecBodyReadTimeoutSeconds`. Owns JSON parse and HTTP+auth. Not the LAPI Client.
_Avoid_: CrowdsecConnection, `AppsecQuery` on LAPI, LAPI captcha, `atomic.Pointer[T]`, Adopt-only timeout or TLS

**Structured AppSec response**:
JSON CrowdSec 1.8 AppSec returns to the bouncer (`action`, `http_status`, `user_body_content`, `user_cookies`, `user_headers`). Listener HTTP 403 carries a remediation envelope; listener 200 is allow.
_Avoid_: LAPI captcha, ban template HTML, `RemoteAddr`

**Challenge**:
AppSec `action` `challenge`. The bouncer writes that envelope to the browser unless a matched captcha action rule already owns the gate (`core_plugin_middleware_action-rules.md`). `/crowdsec-internal/challenge/*` must use the same middleware so the callback is not sent to origin.
_Avoid_: CrowdSec LAPI captcha remediation

**Client disconnected**:
The client stopped sending its AppSec-forwardable body mid-copy, before any body-read deadline fired (`ErrClientDisconnected`: `context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF`). Not an AppSec verdict and not `bouncerAppsecFailureAction`. The bouncer stops without origin, logs TRACE, and may set `bouncerRemediationHeadersCustomName` to `error:client-disconnected`.
_Avoid_: GetBody ban, unreadable body, FailureAction passthrough

**Body of unknown length**:
A client body with no declared length (`ContentLength < 0`: HTTP/1.1 chunked, HTTP/2 or HTTP/3 without `Content-Length`), tested by `isBodyLengthUnknown`. It is read and inspected like any other forwardable body; only its read runs under `appsecBodyReadTimeoutSeconds`.
_Avoid_: unreadable body, `isBodyUnreadable`, HTTP/2 body drop

**Body read timeout**:
A body of unknown length that neither ended nor reached `appsecBodyLimit` within `appsecBodyReadTimeoutSeconds` (`ErrBodyReadTimeout`). Not an AppSec verdict and not `bouncerAppsecFailureAction`: the bouncer serves its own ban (`headerReason` `appsec-body-timeout`, origin `plugin:appsec_body_timeout`). Takes precedence over client disconnected.
_Avoid_: unreadable-body drop, FailureAction ban, `appsec-failure` for a slow body

## Overview

`appsec.Client.Query` owns the AppSec HTTP round-trip and JSON parse. `Bouncer` owns writing the client response or the operator ban template. Client IP is `pkg/ip.GetRemoteIP` only; AppSec handlers take `clientrequest.Request` still named `req`.

## How to use

- Enable with existing `appsecEnabled`. Do not add a bot-detection plugin key.
- Open with `appsec.Open` (reclaim by middleware name plus AppSec URL+key+effective body limit+TLS+`appsecHttpTimeoutSeconds`+`appsecBodyReadTimeoutSeconds`). A knob change is a new Client. Do not construct the AppSec client inside `lapi.New`. Do not use `atomic.Pointer[T]`.
- `newTransport` sets `http.Client.Timeout` and stored `httpTimeoutSeconds` from `cfg.AppsecHTTPTimeoutSeconds`. Do not inherit from a shared default. Store the knob so `fieldsDiffer` sees a timeout change. Query uses that stored client.
- `action` allow or empty 200 → `next`. `ban` → `handleBanServeHTTP` with `headerReason` `appsec` (`ban:appsec` when the remediation header is set). Any other non-allow action (challenge, AppSec captcha HTML) → relay, except a matched captcha action rule: non-empty `challenge` body MUST NOT relay (`applyAppsecServeHTTP` returns false so the plugin gate runs). Missing or empty-string `challenge` `user_body_content` → `handleBanServeHTTP` with `headerReason` `appsec-challenge-empty` (`ban:appsec-challenge-empty`) before `WriteHeader`. Empty `captcha` body still relays `http_status` (not the operator ban page). AppSec `captcha` is not `pkg/captcha`.
- On relay, when `bouncerRemediationHeadersCustomName` is set, write `formatAppsecRelayHeader(decision.Action)`: `captcha` → `captcha:appsec`, `challenge` → `captcha:challenge`, any other action → `{sanitized-action}:appsec` (trim; strip CR/LF/TAB; `:` → `_`). Do not copy raw `decision.Action`. AppSec unpublished / Query error / unusable verdict fail-closed through `headerReason` `appsec-failure` (`ban:appsec-failure` or `captcha:appsec-failure`).
- On relay, assign `user_headers` onto the writer (`rw.Header()[canonical] = values`): same name replaces, including CSP. Skip hop-by-hop names and `Set-Cookie` in that map. `Header().Add("Set-Cookie")` once per `user_cookies` entry. Do not append a second same-name header and do not join cookies with commas.
- AppSec HTTP 500, HTTP 401, unexpected listener statuses (not 200, not 403, not 500, not 502/503/504) with no parseable JSON `action`, unreachable (transport failure or listener HTTP 502/503/504), and AppSec response-body io errors use per-router `bouncerAppsecFailureAction` (`passthrough` | `ban` | `captcha`), not the three removed block bools. `captcha` here is `pkg/captcha`, not AppSec JSON `action: captcha`. A response-body io error keeps `appsecQuery:readBody`. Oversized AppSec bodies do not use this action. A **body read timeout** is not FailureAction: `Query` returns `ErrBodyReadTimeout`, AppSec is not called, and `applyAppsecServeHTTP` bans with `headerReasonAppsecBodyTimeout` and `lapi.OriginPluginAppsecBodyTimeout` whatever the action. A **client disconnect** while buffering the forwardable body is not FailureAction: `Query` returns `ErrClientDisconnected`, AppSec is not called, origin is not called, TRACE only, optional `error:client-disconnected` header. Unclassified client-body read faults keep `appsecQuery:GetBody` and today's ban wiring.
- Always cap the copy with `io.LimitReader` at the Client's `appsecBodyLimit`. `configuration.EffectiveAppsecBodyLimit` maps a value `<= 0` to `DefaultAppsecBodyLimit` (10485760) in both `appsec.Prepare` (written back so the reclaim identity sees it) and `appsec.New`. There is no unlimited mode. Origin gets the copied bytes followed by the rest of the client body (`io.MultiReader`).
- Copy the client body only when `hasBodyForAppsec` says so: body present, not `http.NoBody`, and `isMethodWithForwardableBody` (POST, PUT, PATCH, DELETE), whatever the HTTP version or `Content-Length`. Everything else is a headers-only GET whose body is never read, so a GET carrying a body is not laundered into a POST at the listener. The real verb always travels on `X-Crowdsec-Appsec-Verb`.
- After the forwarded bytes exist, omit client `Content-Length` and every hop-by-hop header (`isHopByHopHeader`); set `Request.ContentLength` and the `Content-Length` header from those bytes on the POST branch only. Reuse `req.IPAddrString()` on `X-Crowdsec-Appsec-Ip`. Set `X-Crowdsec-Appsec-Uri` from `req.AbsoluteURL()` (`core_plugin_clientrequest_inbound-request.md`). Do not set that header from `URL.String()` or `URL.Scheme`. Do not derive scheme from proto or TLS. Set `X-Crowdsec-Appsec-Http-Version` from inbound `ProtoMajor` / `ProtoMinor` as two ASCII digits; omit when `ProtoMajor` is 0. Do not parse `Request.Proto`.
- For a body of unknown length, `armBodyReadDeadline` starts a `time.AfterFunc` timer of `appsecBodyReadTimeoutSeconds` before the read; a declared length arms nothing and keeps Traefik's `readTimeout`. On fire, `cutClientBodyRead` calls `ResponseController.SetReadDeadline(time.Now())` and falls back to `Body.Close` when there is no controller or it refuses. After the read, ask `bodyReadDeadlineFired` (stops an unfired timer) **before** classifying the read error; when it fired, WARN `msgBodyReadTimeout` through `logger.Debounced` for 5 seconds with `ip`, `method`, `host`, `path`, `timeoutSeconds` and return `ErrBodyReadTimeout`.
- Pass `http.NewResponseController(rw)` into `Query` from `applyAppsecServeHTTP` (sole owner of `rw`). `nil` is allowed (unit tests) and falls back to `Body.Close`.
- Drain and close every non-nil AppSec `Do` response before return, including 502/503/504. Transport errors have no body.
- Route `PathPrefix(/crowdsec-internal/challenge)` through the same middleware; service backend is the AppSec listener.
- Copy request `Cookie` through to AppSec (already copied with other headers). Do not parse `__crowdsec_challenge` in this plugin.

## Pattern snippet

```go
decision, err := appsecClient.Query(req, pol, http.NewResponseController(rw))
if errors.Is(err, appsec.ErrBodyReadTimeout) {
	b.handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsecBodyTimeout, lapi.OriginPluginAppsecBodyTimeout)
	return true
}
```

## Key files

- `pkg/appsec/`
- `pkg/appsec/query.go`
- `pkg/appsec/client_http.go`
- `pkg/appsec/session.go`
- `pkg/configuration/configuration.go` (`EffectiveAppsecBodyLimit`, `DefaultAppsecBodyReadTimeoutSeconds`)
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/remediation_header.go`
- `pkg/clientrequest/request.go`

## Gotchas

- Challenge always arrives as AppSec listener 403 plus JSON `action: challenge`. Browser status is `http_status` (often 200, sometimes 307).
- A matched captcha action rule wins over a non-empty AppSec challenge envelope. Empty challenge body still fail-closed bans (`headerReasonAppsecChallengeEmpty`) and WARNs `warnCaptchaSuperseded`.
- Empty-challenge fail-closed runs in `applyAppsecServeHTTP` before `handleAppsecResponseServeHTTP` and before `WriteHeader`. Do not commit status first.
- Relay replaces same-name `user_headers` (assign, do not `Add`) and `Add`s each `user_cookies` string as its own `Set-Cookie`.
- Missing `http_status` is 200. Values outside 100–999 use `remediationStatusCode`.
- Do not send `/crowdsec-internal/challenge/*` to origin.
- `Query` `captcha` failure action is `ErrFailureCaptcha` → `pkg/captcha`. Do not treat that error as AppSec JSON `action: captcha`.
- Empty `appsecKey` still falls back to `lapiKey` in `appsec.Prepare`. Call `lapi.Prepare` first.
- HTTP 200 with an empty, invalid, or action-less body is allow. HTTP 403 with an empty or invalid body is a fail-closed ban. A non-empty `action` on 200 or 403 is the verdict. Drain those bodies so keep-alive can reuse the slot.
- HTTP 500 uses `bouncerAppsecFailureAction` and logs Info `appsecQuery:failure` through `logger.Debounced` for 5 seconds. HTTP 401 uses that same action even when the body is JSON with an `action`, and logs WARN `Remediation component is not authenticated.` through `logger.Debounced` for 5 seconds. Every other listener status, including 502/503/504, uses that same action even when the body is JSON with an `action`. It logs WARN `The remediation component returned an unexpected status code` with attr `statusCode`, through `logger.Debounced` for 5 seconds. The key is the message text, so another unexpected status inside those 5 seconds does not log again. A 401 does not consume that window. A transport failure with no HTTP response stays Error `appsecQuery:unreachable`.
- One method predicate. `isMethodWithForwardableBody` (POST, PUT, PATCH, DELETE) is the only method gate for copying a body. Do not reintroduce a separate drop set or a body class keyed on `Content-Length` or HTTP version: a client controls both.
- Client-body read outcomes, in this order. **Body read timeout** (`bodyReadDeadlineFired`): `ErrBodyReadTimeout`, even when the cut read looks like a disconnect or the read raced to success. **Client disconnected** (`isClientGoneBodyReadErr` during the buffer `io.ReadAll`): `Query` returns `ErrClientDisconnected`; bouncer TRACE-logs, optional `error:client-disconnected` header, no ban, no origin, no FailureAction. **Unclassified** `GetBody` read errors (including Traefik's own `readTimeout`, a wrapped `os.ErrDeadlineExceeded`): keep `fmt.Errorf("appsecQuery:GetBody %w", err)` and the `appsec-failure` ban wiring.
- Client-gone is `errors.Is` for `context.Canceled`, `context.DeadlineExceeded`, and `io.ErrUnexpectedEOF` in `isClientGoneBodyReadErr` only. A server read deadline is `os.ErrDeadlineExceeded`, not `context.DeadlineExceeded`; classify the plugin's deadline from its own timer, never from the read error. Do not `WriteHeader` on that path.
- Behind Traefik v3.7.11 the controller does not reach the HTTP/1.1 connection and `Body.Close` cannot unblock an HTTP/1 read: a stalled HTTP/1.1 body is still banned as a body read timeout, but only once the client ends it or Traefik's `readTimeout` fires. HTTP/2 is cut at the deadline (`knowledge/debt/2026-11-14-appsec-body-timeout-http1-cut-behind-traefik.md`).
- Use `time.AfterFunc` plus `Stop` on the request path, not a `select` on a timer channel (Yaegi v0.16.1 `_select`). Put `remediationHeadersCustomName` in Traefik access-log headers if you want disconnects in access logs.
- Do not strip header names listed in the client's own `Connection` header, even though RFC 7230 tells a proxy to. This forward is an inspection copy, so that rule would let a client hide `Cookie` (or anything else) from the WAF. The static hop-by-hop list is the whole filter.
- Classify AppSec response-body io failures with `errors.Is` on the package-local sentinel. Do not match the `appsecQuery:readBody` prefix. Oversized AppSec bodies stay a different error and skip FailureAction.
- Do not pass `0` into `io.LimitReader` (`N <= 0` is immediate EOF). Read the limit through `EffectiveAppsecBodyLimit`, never raw config.
- AppSec TLS, body limit, `appsecHttpTimeoutSeconds`, and `appsecBodyReadTimeoutSeconds` live on the ownership key. A change is a new Client. Do not apply those knobs with `AdoptTransport`.
