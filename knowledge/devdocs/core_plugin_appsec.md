# AppSec query and challenge relay

## Language

**AppSec Client**:
The reclaim value for one CrowdSec AppSec listener (`pkg/appsec`). Keyed by middleware name plus host, path, resolved key, body limit, TLS, `appsecHttpTimeoutSeconds`, and `appsecUnhealthyBackOffPeriodSecs`. Owns JSON parse, HTTP+auth, and the admission gate. Not the LAPI Client.
_Avoid_: CrowdsecConnection, `AppsecQuery` on LAPI, LAPI captcha, `atomic.Pointer[T]`, Adopt-only timeout or TLS

**Gate skip**:
A denied AppSec admission (`ErrGateSkip`). Query does not call AppSec and does not apply `bouncerAppsecFailureAction`. The bouncer continues (then ModSec if subscribed). ModSec skips the same way (`modsecurity.ErrGateSkip`). Not an admitted miss and not client disconnected.
_Avoid_: FailureAction, treating skip as ban, Reporting a denied Allow

**Structured AppSec response**:
JSON CrowdSec 1.8 AppSec returns to the bouncer (`action`, `http_status`, `user_body_content`, `user_cookies`, `user_headers`). Listener HTTP 403 carries a remediation envelope; listener 200 is allow.
_Avoid_: LAPI captcha, ban template HTML, `RemoteAddr`

**Challenge**:
AppSec `action` `challenge`. The bouncer writes that envelope to the browser unless a matched captcha action rule already owns the gate (`core_plugin_middleware_action-rules.md`). `/crowdsec-internal/challenge/*` must use the same middleware so the callback is not sent to origin.
_Avoid_: CrowdSec LAPI captcha remediation

**AppSec captcha verdict**:
AppSec `action` `captcha`. CrowdSec sends it without a page (`GenerateResponse` fills a body only for `challenge`; `knowledge/research/ext_crowdsec_appsec_protocol/`), so the bouncer serves this router's captcha gate with origin `appsec` (`serveAppsecCaptchaGate`). Not a relayed envelope.
_Avoid_: AppSec captcha HTML, envelope relay, `bouncerAppsecFailureAction` captcha

**Client disconnected**:
The client stopped sending a readable AppSec-forwardable body mid-copy (`ErrClientDisconnected`: the inbound request context is canceled, or the read error is `context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF`). Not an AppSec verdict and not `bouncerAppsecFailureAction`. The bouncer stops without origin, logs TRACE, and may set `bouncerRemediationHeadersCustomName` to `error:client-disconnected`.

**Client body read error**:
Any other failure reading that body while the request context is still live (`ErrClientBodyRead`), for example the server read timeout on a slow HTTP/2 upload. Not an AppSec verdict and not `bouncerAppsecFailureAction`. The bouncer answers 400 without origin, ban template, or dropped metrics, logs DEBUG, and may set `error:client-body-read`.
_Avoid_: GetBody ban, unreadable body, FailureAction passthrough

## Overview

`appsec.Client.Query` owns the AppSec HTTP round-trip and JSON parse. When backoff is on, Query admits then Reports. `Bouncer` owns writing the client response or the operator ban template. Client IP is `pkg/ip.GetRemoteIP` only; AppSec handlers take `clientrequest.Request` still named `req`.

## How to use

- Enable with existing `appsecEnabled`. Do not add a bot-detection plugin key.
- Open with `appsec.Open` (reclaim by middleware name plus AppSec URL+key+body limit+TLS+`appsecHttpTimeoutSeconds`+`appsecUnhealthyBackOffPeriodSecs`). A knob change is a new Client. Do not construct the AppSec client inside `lapi.New`. Do not use `atomic.Pointer[T]`.
- When `appsecUnhealthyBackOffPeriodSecs` is greater than 0, `admission.New` builds one gate on `backendbackoff.Gate` from dest utilities `v1.0.7`. Default period is 30. `0` builds no gate. The period is the only knob: the trip rule is fixed in `pkg/admission` (`TripFailures` 5, `FailureRatio` 0.30; each failure spends 1, each success earns back `0.30/0.70`, so 5 failures in a row trip), and the cooldown does not grow (max equals the base). Do not set `Jitter` or `TTL`. `Close` Closes a non-nil Gate.
- Query `Allow`s before the AppSec hop. Denied Allow returns `ErrGateSkip`: do not call AppSec, do not apply FailureAction. `applyAppsecServeHTTP` treats that error as continue (then ModSec if subscribed). Admitted transport failure, HTTP 500, an unexpected listener status, or a response-body io error `Record`s failure then applies FailureAction. HTTP 401 `Record`s success (configuration error, not an outage) and still applies FailureAction. A usable verdict `Record`s success. Inbound cancel (`wafhop.IsInboundCanceled`) does not Record.
- `newTransport` sets `http.Client.Timeout` and stored `httpTimeoutSeconds` from `cfg.AppsecHTTPTimeoutSeconds`. Do not inherit from a shared default. Store the knob so `fieldsDiffer` sees a timeout change. Query uses that stored client.
- `action` allow or empty 200 → `next`, except `/crowdsec-internal/challenge/`. `ban` → `handleBanStatusServeHTTP` with `headerReason` `appsec` (`ban:appsec` when the remediation header is set) and the status from `appsecBanStatusCode`: an `http_status` from 200 to 599 is relayed (403 by default, 429 for `RateLimit()`, or the `SetReturnCode()` value); zero, missing, or out of range uses `remediationStatusCode`. `captcha` → `serveAppsecCaptchaGate` (captcha gate, origin `appsec`, header `captcha:appsec`, downgrade ban reason `APPSEC` with `ban:captcha-downgrade`); never relay its `http_status` or body. Non-empty `challenge` → relay. Missing or empty-string `challenge` `user_body_content` → `handleBanServeHTTP` with `headerReason` `appsec-challenge-empty` (`ban:appsec-challenge-empty`) before `WriteHeader`. Any other action: non-empty body → relay; empty body → `handleBanServeHTTP` with `headerReason` `appsec-action-empty`. With a matched captcha action rule, `captcha` and non-empty `challenge` return false so the rule's gate runs.
- After `applyAppsecServeHTTP` returns false on the non-rule path, `serveAppSec` sends a POST carrying `crowdsec_captcha_challenge=v1` to `serveAppsecCaptchaGate` when `isCaptchaFormAnswer` holds: this router has a usable captcha client (`usableCaptcha`: subscribed, published, Valid) and `HasChallengeMarker` finds the marker. AppSec judges each request alone: a rule that matched the GET may allow the form POST. Do not move this check before the AppSec Query; AppSec bans on that POST must still apply.
- When AppSec is in use (subscribed; `foldActionRules` never leaves `SkipAppsec` set on this prefix, so a bypass rule cannot opt it out) and nothing in `answerAppSec` wrote (captcha action rule, `applyAppsecServeHTTP`, or the captcha-form gate), a path under `/crowdsec-internal/challenge/` (`isCrowdsecChallengeCallbackPath`) gets `http.NotFound` and `serveAppSec` returns true, so `next` is not called. This covers allow, failure-action passthrough, and a cleared gate, including a solved captcha action rule. Keep this check in `serveAppSec` after `answerAppSec`.
- On relay, when `bouncerRemediationHeadersCustomName` is set, write `formatAppsecRelayHeader(decision.Action)`: `challenge` → `captcha:challenge`, any other relayed action → `{sanitized-action}:appsec` (trim; strip CR/LF/TAB; `:` → `_`). Do not copy raw `decision.Action`. AppSec unpublished / Query error / unusable verdict fail-closed through `headerReason` `appsec-failure` (`ban:appsec-failure` or `captcha:appsec-failure`).
- On relay, `recordDropped` once with origin `appsec`, except when `req.URL.Path` is under `/crowdsec-internal/challenge/` (`isCrowdsecChallengeCallbackPath`): `fpscanner.js`, `pow-worker.js`, and `submit` are the same solve as the page. The skip covers both `dropped` series (request and byte) and only the relay; bans and the captcha gate count as before.
- On relay, assign `user_headers` onto the writer (`rw.Header()[canonical] = values`): same name replaces, including CSP. Skip hop-by-hop names and `Set-Cookie` in that map. `Header().Add("Set-Cookie")` once per `user_cookies` entry. Do not append a second same-name header and do not join cookies with commas.
- AppSec HTTP 500, HTTP 401, unexpected listener statuses (not 200, not 403, not 500, not 502/503/504) with no parseable JSON `action`, unreachable (transport failure or listener HTTP 502/503/504), AppSec response-body io errors, and an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH use per-router `bouncerAppsecFailureAction` (`passthrough` | `ban` | `captcha`), not the three removed block bools, only when the hop was admitted (the gate allowed the call, or no gate exists). Default stays `ban`. `captcha` here is `pkg/captcha`, not AppSec JSON `action: captcha`. A response-body io error keeps `appsecQuery:readBody`. Oversized AppSec bodies do not use this action. A **Gate skip** is not FailureAction (`ErrGateSkip`). Every failure above except HTTP 401 spends gate budget; a 401 is a configuration error, so it reports success to the gate. A **client disconnect** while buffering a readable forwardable body is not FailureAction: `Query` returns `ErrClientDisconnected`, AppSec is not called, origin is not called, TRACE only, optional `error:client-disconnected` header. Any other client-body read fault is `ErrClientBodyRead` (400, no ban, no FailureAction).
- Buffer with `wafhop.ReadBody(req, appsecBodyLimit, wafhop.TruncateAtLimit)` (`core_plugin_wafhop_shared-request.md`). `appsecBodyLimit` `0` is unlimited. A positive limit still caps the copy; the bytes past it still reach origin. Omitted default stays 10485760.
- Copy a readable body only when `isMethodWithForwardableBody` says so (POST, PUT, PATCH, DELETE) and the body is not `http.NoBody`. Everything else is a headers-only GET whose body is never read, so a GET carrying a body is not laundered into a POST at the listener. The real verb always travels on `X-Crowdsec-Appsec-Verb`.
- After the forwarded bytes exist, omit client `Content-Length` and every hop-by-hop header (`wafhop.CopyEndToEndHeaders`); set `Request.ContentLength` and the `Content-Length` header from those bytes on the POST branch only. Reuse `req.IPAddrString()` on `X-Crowdsec-Appsec-Ip`. Set `X-Crowdsec-Appsec-Uri` from `req.AbsoluteURL()` (`core_plugin_clientrequest_inbound-request.md`). Do not set that header from `URL.String()` or `URL.Scheme`. Do not derive scheme from proto or TLS. Set `X-Crowdsec-Appsec-Http-Version` from inbound `ProtoMajor` / `ProtoMinor` as two ASCII digits; omit when `ProtoMajor` is 0. Do not parse `Request.Proto`.
- Drain and close every non-nil AppSec `Do` response before return, including 502/503/504. Transport errors have no body.
- Route `PathPrefix(/crowdsec-internal/challenge)` through the same middleware; service backend is the AppSec listener.
- Copy request `Cookie` through to AppSec (already copied with other headers). Do not parse `__crowdsec_challenge` in this plugin.

## Pattern snippet

```go
decision, err := b.appsecClient.Query(req, pol)
```

## Key files

- `pkg/appsec/`
- `pkg/appsec/query.go`
- `pkg/admission/admission.go`
- `pkg/appsec/client_http.go`
- `pkg/appsec/session.go`
- `pkg/bouncer/bouncer.go`
- `pkg/bouncer/bouncer_serve_appsec.go`
- `pkg/bouncer/bouncer_serve_appsec_verdict.go`
- `pkg/bouncer/remediation_header.go`
- `pkg/clientrequest/request.go`

## Gotchas

- Challenge always arrives as AppSec listener 403 plus JSON `action: challenge`. Browser status is `http_status` (often 200, sometimes 307).
- A matched captcha action rule wins over a non-empty AppSec challenge envelope. Empty challenge body still fail-closed bans (`headerReasonAppsecChallengeEmpty`) and WARNs `warnCaptchaSuperseded`.
- Empty-challenge fail-closed runs in `answerAppsecVerdict` before `handleAppsecResponseServeHTTP` and before `WriteHeader`. Do not commit status first.
- Relay replaces same-name `user_headers` (assign, do not `Add`) and `Add`s each `user_cookies` string as its own `Set-Cookie`.
- That replace only beats headers already on the writer. Traefik's `headers` middleware (`contentSecurityPolicy` and `customResponseHeaders`) wraps the writer in `middlewares.ResponseModifier` and `Set`s its headers inside `WriteHeader`, after the plugin. Listed before the bouncer, it overwrites the challenge CSP; listed after, it never runs on a plugin answer. No plugin code fixes this: deleting or loosening the CSP is overwritten the same way, and `Unwrap()` past the modifier would skip every outer wrapper and drop the operator's other security headers. The README section "Keep a Content-Security-Policy without breaking the challenge or the captcha" tells operators to list the CSP `headers` middleware after the bouncer.
- Missing `http_status` is 200. Values outside 100–999 use `remediationStatusCode`.
- Do not send `/crowdsec-internal/challenge/*` to origin.
- `Query` `captcha` failure action is `ErrFailureCaptcha` → `pkg/captcha`. Do not treat that error as AppSec JSON `action: captcha`.
- Empty `appsecKey` still falls back to `lapiKey` in `appsec.Prepare`. Call `lapi.Prepare` first.
- HTTP 200 with an empty, invalid, or action-less body is allow. HTTP 403 with an empty or invalid body is a fail-closed ban. A non-empty `action` on 200 or 403 is the verdict. Drain those bodies so keep-alive can reuse the slot.
- HTTP 500 uses `bouncerAppsecFailureAction` and logs Info `appsecQuery:failure` through `logger.Debounced` for 5 seconds. HTTP 401 uses that same action even when the body is JSON with an `action`, and logs WARN `Remediation component is not authenticated.` through `logger.Debounced` for 5 seconds. Every other listener status, including 502/503/504, uses that same action even when the body is JSON with an `action`. It logs WARN `The remediation component returned an unexpected status code` with attr `statusCode`, through `logger.Debounced` for 5 seconds. The key is the message text, so another unexpected status inside those 5 seconds does not log again. A 401 does not consume that window. A transport failure with no HTTP response stays Error `appsecQuery:unreachable`.
- Two method predicates, on purpose. `wafhop.IsMethodWithBody` (POST, PUT, PATCH) answers "is an *unreadable* body a drop candidate"; `isMethodWithForwardableBody` (POST, PUT, PATCH, DELETE) answers "is a *readable* body copied to AppSec". Do not collapse them: DELETE must forward a readable body and must never re-enter the drop set.
- Client-body shapes. **Unreadable** (`wafhop.IsBodyUnreadable`: HTTP/2+ without Content-Length): passthrough still queries AppSec with headers-only GET; ban on POST/PUT/PATCH drops without AppSec. **Client disconnected** (`wafhop.IsClientGone` inside `wafhop.ReadBody`): `Query` returns `ErrClientDisconnected`; bouncer TRACE-logs, optional `error:client-disconnected` header, no ban, no origin, no FailureAction. **Client body read error** (any other read error with a live context): `Query` returns `ErrClientBodyRead` (`wafhop:clientBodyRead: <read error>`); bouncer DEBUG-logs, answers 400, optional `error:client-body-read` header, no ban, no origin, no dropped metrics, no FailureAction.
- Client-gone is a canceled inbound request context, or `errors.Is` for `context.Canceled`, `context.DeadlineExceeded`, and `io.ErrUnexpectedEOF`, in `wafhop.IsClientGone` only. Check the context first: an HTTP/2 stream reset fails the read with an unexported stream error that does not wrap `context.Canceled`, and an HTTP/1.1 TCP reset or read timeout fails it with a `*net.OpError`; net/http cancels the context before both. A server read timeout on HTTP/2 wraps `os.ErrDeadlineExceeded` (not `context.DeadlineExceeded`) and leaves the context live, so it is `ErrClientBodyRead`. `pkg/appsec/zzz_client_body_read_protocols_test.go` drives each case through a real net/http server. Mid-read cancel on a readable CL-known body is client disconnected, not unreadable; do not extend `wafhop.IsBodyUnreadable` for that case. Do not `WriteHeader` on that path. Put `remediationHeadersCustomName` in Traefik access-log headers if you want disconnects in access logs.
- Do not strip header names listed in the client's own `Connection` header, even though RFC 7230 tells a proxy to. This forward is an inspection copy, so that rule would let a client hide `Cookie` (or anything else) from the WAF. The static hop-by-hop list in `wafhop.IsHopByHopHeader` is the whole filter, for ModSec too.
- Classify AppSec response-body io failures with `errors.Is` on the package-local sentinel. Do not match the `appsecQuery:readBody` prefix. Oversized AppSec bodies stay a different error and skip FailureAction.
- Do not pass `0` into `io.LimitReader` (`N <= 0` is immediate EOF).
- AppSec TLS, body limit, `appsecHttpTimeoutSeconds`, and `appsecUnhealthyBackOffPeriodSecs` live on the ownership key. A change is a new Client. Do not apply those knobs with `AdoptTransport`.
- Do not copy Gate into this repository. Do not treat a denied Allow as FailureAction even when that action is `ban`. Real-stack AppSec routes pin `appsecUnhealthyBackOffPeriodSecs: 0` so FailureAction cases are not skipped by the default gate.
