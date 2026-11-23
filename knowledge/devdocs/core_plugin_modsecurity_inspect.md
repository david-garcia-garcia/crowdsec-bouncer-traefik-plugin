# ModSecurity inspect

## Language

**Inspect copy**:
The sidecar HTTP request this plugin builds from the inbound request: same method and `RequestURI`, `Host` set to inbound `req.Host`, headers as Traefik left them minus the shared hop-by-hop list and `Content-Length` (`wafhop.CopyEndToEndHeaders`), and the readable body with a `Content-Length` rebuilt from the forwarded bytes. Not an AppSec JSON forward.
_Avoid_: `X-Crowdsec-Appsec-*`, setting `X-Real-IP`, appending `RemoteAddr` to `X-Forwarded-For`

**Copied block**:
Sidecar HTTP 3xx or 4xx copied to the client by `modsecurity.WriteBlock` (end-to-end headers except `Server`, status, body). `next` is not called. Not a WAF failure.
_Avoid_: following a sidecar 3xx, treating 5xx as a block page, writing the block inside `Inspect`

**WAF failure**:
The sidecar gave no verdict (`modsecurity.ErrUnavailable`): transport error or timeout, sidecar HTTP 5xx, a request that could not be built, an admission error, or a POST/PUT/PATCH body streamed without a length when the failure action is not `passthrough`. The sidecar 5xx body is not forwarded. The request follows the failure action. Not a copied block.
_Avoid_: copying the 5xx body, treating 5xx as CRS ban

**Failure action**:
The per-router `bouncerModsecFailureAction` (`passthrough` | `ban` | `captcha`) applied on a WAF failure or a missing subscribed Client. Same values and validation as `bouncerLapiFailureAction` and `bouncerAppsecFailureAction`, but the default is `passthrough` (`configuration.EffectiveModsecFailureAction("")`).
_Avoid_: `bouncerModsecFailMode`, `open`/`close`, an empty 502

## Overview

`modsecurity.Client.Inspect` copies the inbound request to `modsecUrl` and classifies the sidecar status. It never writes the client response: `serveModSec` does. Client reclaim lives on `core_plugin_modsecurity_client.md`. Serve order: `core_plugin_middleware.md`. Spec: `core_plugin_modsecurity_inspect`.

## How to use

- Call `serveModSec` after AppSec. True means the response was written. False means ServeHTTP calls `next`.
- Skip inspect when `ActionMatch.SkipModsec` or the route did not subscribe. Do not buffer the body, do not consult the Gate, and do not call the sidecar.
- A missing subscribed Client applies that router's failure action (`applyModsecFailureAction`).
- `Inspect(req, failureAction)` returns `(*http.Response, error)`. `nil, nil` is allow. A non-nil response is a block: set `ban:modsec` (when `bouncerRemediationHeadersCustomName` is set), `recordDropped` with origin `modsec` and remediation `ban`, then `modsecurity.WriteBlock(rw, resp)`, which closes it.
- Errors: `modsecurity.ErrUnavailable` → failure action. `modsecurity.ErrGateSkip` → `next`, no failure action. `modsecurity.ErrBodyTooLarge` (= `wafhop.ErrBodyTooLarge`) → HTTP 413, sidecar not called. `wafhop.ErrClientDisconnected` and `wafhop.ErrClientBodyRead` → the shared bouncer handlers (no ban, no failure action).
- Order inside Inspect: body (shared rules, `core_plugin_wafhop_shared-request.md`) → Gate `Admit` → sidecar hop. AppSec `Query` uses the same order.
- Body: there is no method list. Any readable body up to `modsecBodyLimit` goes to the sidecar, GET and OPTIONS included; CRS decides (920170/920171 block a body on GET/HEAD). An unreadable body (`wafhop.IsBodyUnreadable`) is never read: on POST, PUT, or PATCH it is `ErrUnavailable` unless the failure action is `passthrough`, which inspects headers only. While `Gate.BackingOff()` it is `ErrGateSkip` instead, and it never takes a ticket. A readable body goes through `wafhop.ReadBody(req, modsecBodyLimit, wafhop.RejectOverLimit)`. A whole body AppSec already buffered is reused.
- Sidecar HTTP 2xx allows (drain, do not copy the sidecar body). Sidecar 3xx/4xx is a block. Sidecar 5xx is a WAF failure: drain, Record failure, return `ErrUnavailable`.
- Failure action: `passthrough` returns false. `ban` writes the ban template with `bouncerRemediationStatusCode`, RemediationReason `MODSEC` (`configuration.ReasonMODSEC`), header `ban:modsec-failure`, origin `plugin:modsec_failure` (`lapi.OriginPluginModsecFailure`). `captcha` serves the router captcha with `captcha:modsec-failure`; a client that already cleared the gate continues.
- Unreachable sidecar and sidecar 5xx log ERROR `crowdsec modsec sidecar unavailable` (`modsecurity.MsgUnavailable`) through `logger.Debounced` for 5 seconds, with `host` and `reason` (`unreachable` plus the transport error in `error`, or `status` plus `statusCode`). Keep that debounce: `modsecUnhealthyBackOffPeriodSecs` defaults to 0, so by default no gate bounds the line. The logged `error` is `transportCause(err)`, the `*url.Error` cause without the URL, because the sidecar URL carries the visitor's path and query. A Gate `Admit` error logs ERROR `fail to admit ModSec request` with `error`, like AppSec.
- When the Client holds a Gate, `Admit` after the body is read and before the sidecar hop. A denied admission returns `ErrGateSkip`: no Record, no sidecar call, no failure action. A usable inspect (2xx or copied 3xx/4xx) Records success. Transport error or sidecar 5xx Records failure.
- Inbound cancel (`wafhop.IsInboundCanceled`) before or during the sidecar hop returns `wafhop.ErrClientDisconnected`: nothing written, no Record, no failure action, no `next`.
- Set sidecar request `Host` to inbound `req.Host`. Copy Traefik headers with `wafhop.CopyEndToEndHeaders` (names the client lists in `Connection` are still copied). Do not set `X-Real-IP`. Do not append `RemoteAddr` to `X-Forwarded-For`. Plugin remediations and logs keep using `pkg/ip.GetRemoteIP` then `clientrequest.New`. Sidecar `REMOTE_ADDR` stays the Traefik-to-sidecar hop unless the CRS image sets `REMOTEIP_*` / `REAL_IP_*`.

## Pattern snippet

```go
blocked, err := client.Inspect(req.Request, b.modsecFailureAction)
switch {
case err == nil && blocked == nil:
	return false
case err == nil:
	b.recordDropped(req, originModsec, "ban")
	b.setRemediationHeader(rw, headerKindBan, headerReasonModsec, "")
	modsecurity.WriteBlock(rw, blocked)
	return true
case errors.Is(err, modsecurity.ErrGateSkip):
	return false
case errors.Is(err, modsecurity.ErrBodyTooLarge):
	http.Error(rw, "Request body too large", http.StatusRequestEntityTooLarge)
	return true
// wafhop.ErrClientDisconnected, wafhop.ErrClientBodyRead: shared handlers
default:
	return b.applyModsecFailureAction(rw, req, match)
}
```

## Key files

- `pkg/modsecurity/inspect.go` (`Inspect`, `WriteBlock`)
- `pkg/modsecurity/client_http.go` (`CheckRedirect`)
- `pkg/bouncer/bouncer_leg_modsec.go` (bind)
- `pkg/bouncer/bouncer_serve_modsec.go` (`serveModSec`, `applyModsecFailureAction`)
- `pkg/bouncer/bouncer_serve_waf.go` (shared client-body answers)
- `pkg/bouncer/bouncer.go` (`ServeHTTP` after AppSec)
- `pkg/httprule/action.go` (`SkipModsec`)

## Gotchas

- The failure action applies to `ErrUnavailable` and a missing subscribed Client only. It does not apply to a copied 3xx/4xx, HTTP 413, a gate skip, or a client-body error.
- A gate skip on either leg continues without that leg and without its failure action. An AppSec skip still runs ModSec, and a ModSec skip still lets AppSec have run first. Failures before the trip still apply the failure action.
- The default is `passthrough`, unlike LAPI and AppSec (`ban`). A sidecar outage lets traffic through unless the operator asks otherwise.
- `CheckRedirect` must return `http.ErrUseLastResponse` so a sidecar 302 is a copied block, not a followed hop.
- Drain leftover sidecar bytes (2xx and 5xx) so the HTTP slot can be reused. Do not forward the 5xx body.
- `WriteBlock` deletes on `rw` only the names the sidecar sends, so `ban:modsec` set before it survives unless the sidecar sends that same header.
