# ModSecurity inspect

## Language

**Inspect copy**:
The sidecar HTTP request this plugin builds from the inbound request: same method and `RequestURI`, `Host` set to inbound `req.Host`, headers copied as Traefik left them. Not an AppSec JSON forward.
_Avoid_: `X-Crowdsec-Appsec-*`, setting `X-Real-IP`, appending `RemoteAddr` to `X-Forwarded-For`

**Copied block**:
Sidecar HTTP 3xx or 4xx copied to the client (status and body). `next` is not called. Hop-by-hop response headers and `Server` are omitted. Not a WAF failure.
_Avoid_: following a sidecar 3xx, treating 5xx as a block page

**WAF failure**:
Sidecar transport error or sidecar HTTP 5xx. The sidecar 5xx body is not forwarded. The request follows FailMode. Not a copied block.
_Avoid_: copying the 5xx body, treating 5xx as CRS ban

**FailMode**:
The per-router enum (`open` | `close`) this plugin applies when ModSec inspect fails or the admission gate denies Allow. Default `open` continues to `next`. `close` writes empty HTTP 502. Empty config is `open`. Not FailureAction.
_Avoid_: FailureAction, `ban`, copying AppSec `passthrough`/`captcha` onto this knob

## Overview

`modsecurity.Client.Inspect` copies the inbound request to `modsecUrl` and classifies the sidecar status. Client reclaim lives on `core_plugin_modsecurity_client.md`. Serve order: `core_plugin_middleware.md`. Spec: `core_plugin_modsecurity_inspect`.

## How to use

- Call `Inspect` from `serveModSec` after AppSec. True means the response was written. False means ServeHTTP calls `next`.
- Skip inspect when `ActionMatch.SkipModsec` or the route did not subscribe. Do not buffer the body, do not apply deny-verbs, do not consult the Gate, and do not call the sidecar.
- A missing subscribed Client uses that router's FailMode (`applyModsecFailMode`).
- Order inside Inspect: deny-verbs-with-body → body-limit copy → Gate `Allow` → sidecar hop.
- Sidecar HTTP 2xx allows (do not copy the sidecar body). Sidecar 3xx/4xx is a copied block; when `bouncerRemediationHeadersCustomName` is set, write `ban:modsec`. Sidecar 5xx is a WAF failure: drain, Report failure, apply FailMode.
- When the Client holds a Gate, `Allow` after deny-verbs and body-limit and before the sidecar hop. Denied Allow does not Report, does not call the sidecar, and follows FailMode. A usable inspect (2xx or copied 3xx/4xx) Reports success. Transport error or sidecar 5xx Reports failure.
- Inbound `context.Canceled` writes empty HTTP 502, does not Report, and does not use FailMode (no `next`).
- Set sidecar request `Host` to inbound `req.Host`. Copy Traefik headers as Traefik left them. Do not set `X-Real-IP`. Do not append `RemoteAddr` to `X-Forwarded-For`. Plugin remediations and logs keep using `pkg/ip.GetRemoteIP` then `clientrequest.New`. Sidecar `REMOTE_ADDR` stays the Traefik-to-sidecar hop unless the CRS image sets `REMOTEIP_*` / `REAL_IP_*`.
- When forwarding a copied block, omit hop-by-hop response headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `Proxy-*`, `Te`, `Trailer`) and `Server`.

## Pattern snippet

```go
if match.SkipModsec || !b.subscribeModsec {
	return false
}
client := b.loadedModSec()
if client == nil {
	return b.applyModsecFailMode(rw)
}
return client.Inspect(rw, req.Request, b.modsecFailMode, b.remediationCustomHeader)
```

## Key files

- `pkg/modsecurity/inspect.go`
- `pkg/modsecurity/client_http.go` (`CheckRedirect`)
- `pkg/bouncer/bouncer_leg_modsec.go`
- `pkg/bouncer/bouncer.go` (`ServeHTTP` after AppSec)
- `pkg/httprule/action.go` (`SkipModsec`)

## Gotchas

- FailMode applies to transport errors, sidecar 5xx, an already-unhealthy gate skip, and a missing subscribed Client. It does not apply to copied 3xx/4xx or deny-verbs HTTP 400 or body-limit HTTP 413.
- AppSec Gate skip (`ErrGateSkip`) continues to ModSec. Do not treat that skip as a ban.
- `CheckRedirect` must return `http.ErrUseLastResponse` so a sidecar 302 is a copied block, not a followed hop.
- Drain leftover sidecar bytes (including 5xx) so the HTTP slot can be reused. Do not forward the 5xx body.
