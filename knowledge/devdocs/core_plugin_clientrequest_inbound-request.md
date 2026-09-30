# Inbound request

## Language

**Inbound request**:
One `clientrequest.Request`: the live `*http.Request` plus the client address GetRemoteIP already chose plus the constructor-owned scheme token. Callers keep the parameter name `req`. Address, scheme, and AbsoluteURL are snapshots from `New`.
_Avoid_: Wrapper, Context, renaming `req` to `client`; a bag for scopes, origin, or captcha state; `context.Value`

**Scheme token**:
The constructor-owned `http` or `https` on that value. Trimmed whole-value `X-Forwarded-Proto` EqualFold `http` or `https` wins; else TLS non-nil → `https`, else `http`.
_Avoid_: `URL.Scheme`, comma-split proto, `wss` as a set proto, hop re-check, writing scheme onto the live request

**AbsoluteURL**:
The client-facing URL captured by `New`: scheme token, `URL.Host` when set otherwise `Request.Host`, path and query preserved.
_Avoid_: `URL.String()` as the AppSec URI, `URL.Scheme`

## Overview

Construct once in `ServeHTTP` after `pkg/ip.GetRemoteIP`. Captcha gate Secure and AppSec `X-Crowdsec-Appsec-Uri` consume this value. The package imports neither bouncer, captcha, nor appsec. GetRemoteIP hop walking stays on `core_plugin_ip.md`.

## How to use

- After `GetRemoteIP`, call `clientrequest.New(httpReq, remoteIP, ipAddr)`. Keep the name `req`.
- When `ipAddr` is non-nil, `New` stores a copy and `RemoteIP()` is `ipAddr.String()`. When it is nil, `RemoteIP()` stays the raw extract for fail logs. `IPType()` is `ip.FamilyOfIP` of that parsed address.
- Do not assign `RemoteIP`, `IPAddr`, scheme, or AbsoluteURL after construction. Do not write scheme onto the live `*http.Request`.
- Pass `req` into captcha `ServeHTTP` / `Check` / `Validate` / `setGateCookie` and AppSec `Query`. Do not pass a parallel `remoteIP` string.
- Leave path-only captcha helpers (`IsCustomResourceRequest`, `IsCaptchaFormPost`, `WriteSolvedRedirect`, `gateCookieValue`, `RequestDomain`) on `*http.Request` / host string.
- AppSec copies `AbsoluteURL()` onto `X-Crowdsec-Appsec-Uri`. Do not rebuild proto-then-TLS in captcha or AppSec. Do not copy GetRemoteIP hop trust into those packages.

## Pattern snippet

```go
remoteIP, ipAddr, err := ip.GetRemoteIP(httpReq, b.serverPoolStrategy, b.forwardedCustomHeader, b.forwardedHeadersInsecure)
req := clientrequest.New(httpReq, remoteIP, ipAddr)
decision, err := appsecClient.Query(req, pol)
```

## Key files

- `pkg/clientrequest/request.go`
- `pkg/bouncer/bouncer.go`
- `pkg/captcha/gate.go`
- `pkg/appsec/query.go`

## Gotchas

- A set proto `http` with TLS set is scheme `http` (cookie not Secure). Dest OR of TLS with proto `https` is gone.
- `wss`, empty, `https,http`, `Forwarded`, `Front-End-Https`, `X-Forwarded-Protocol`, `X-Scheme`, and `URL.Scheme` are not a set proto. TLS non-nil then `https`, else `http`.
- Traefik origin-form requests have empty `URL.Scheme` and `URL.Host`. AbsoluteURL uses `Request.Host` then.
- Later edits to `Host`, `URL`, or the passed `net.IP` do not change the snapshots `New` stored.
