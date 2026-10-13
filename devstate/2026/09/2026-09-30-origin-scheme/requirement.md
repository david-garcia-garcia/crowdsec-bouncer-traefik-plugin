# Requirement
IssueKey: 2026-09-30-origin-scheme

Build one shared origin scheme for the inbound request, and use it for both the captcha gate cookie Secure flag and the CrowdSec AppSec URI.

1. A new leaf package holds the inbound-request wrapper that today lives unexported in `pkg/bouncer/clientrequest.go`. The package imports neither bouncer, captcha, nor appsec. Bouncer fills it once in ServeHTTP after GetRemoteIP. Captcha and AppSec receive that value instead of a bare `*http.Request` plus a parallel remoteIP string.

2. The package owns the scheme rule and sets it in the constructor. Callers do not assign it later. Rule: if `X-Forwarded-Proto`, trimmed, matches the whole value `http` or `https` case-insensitively, that token is the scheme. No comma split. `wss`, empty, `https,http`, `Forwarded`, `Front-End-Https`, `X-Forwarded-Protocol`, `X-Scheme`, and `URL.Scheme` are not a set proto. When the proto is not an exact `http` or `https`, use `Request.TLS`: `https` when TLS is non-nil, otherwise `http`. Do not re-check `forwardedHeadersTrustedIps` or `ForwardedHeadersInsecure`. Do not write the scheme back onto the live `http.Request` that Traefik and next still hold.

3. Captcha sets the gate cookie Secure when that scheme is `https`. Captcha must not read `X-Forwarded-Proto` or `Request.TLS` itself. This replaces today's OR in `pkg/captcha/gate.go` `setGateCookie` (TLS or proto https). Explicit proto `http` with TLS set yields scheme `http` and a cookie that is not Secure.

4. AppSec `X-Crowdsec-Appsec-Uri` is an absolute client-facing URI: that scheme, `Request.Host` when `URL.Host` is empty, path and query preserved. AppSec must not take the scheme from `URL.Scheme`. Today `pkg/appsec/query.go` sends `httpReq.URL.String()`, which is path-only on a normal Traefik server request, so CrowdSec 1.8 omits Secure on the bot-detection challenge cookie (`pkg/appsec/challenge` in CrowdSec checks `request.URL.Scheme == "https"`).

5. A real end-to-end test forges requests with and without TLS, using `X-Forwarded-Proto`, and asserts the Secure flag on both cookies: the captcha gate cookie (`crowdsec_captcha_gate`) and the AppSec bot-detection challenge cookie (`__crowdsec_challenge`).

Out of scope for the ask (do not take them): changing GetRemoteIP hop walking; trusting URL.Scheme; copying raw wss into the URI; re-deriving hop trust inside captcha.

## Current (code)
- Unexported `clientRequest` embeds `*http.Request` plus `ipAddr`, `ipType`, `remoteIP`. No scheme field. No constructor. `pkg/bouncer/clientrequest.go`
- `ServeHTTP` calls `ip.GetRemoteIP` then assigns a struct literal. `pkg/bouncer/bouncer.go` `pkg/ip/checker.go`
- Captcha is still a bare request plus a parallel IP string: `ServeHTTP(rw, r, remoteIP, …)`, `Check(r, remoteIP)`, `Validate(r, remoteIP)`. Bouncer passes `req.Request` and `req.remoteIP`. `pkg/captcha/captcha.go` `pkg/bouncer/bouncer.go`
- `setGateCookie` sets `Secure` when `r.TLS != nil` **or** trimmed `X-Forwarded-Proto` EqualFold `https` (whole value). It reads proto and TLS itself. Explicit `http` with TLS set still Secure (OR). `pkg/captcha/gate.go`
- Gate unit tests cover forwarded https, TLS, and http/wss/absent/empty with TLS nil. They do not cover proto `http` plus TLS. `pkg/captcha/zzz_gate_test.go`
- AppSec `Query(ip string, httpReq *http.Request, pol Policy)`. Bouncer calls `Query(req.remoteIP, req.Request, pol)`. `pkg/appsec/query.go` `pkg/bouncer/bouncer.go`
- `X-Crowdsec-Appsec-Uri` is `httpReq.URL.String()`. Host header is `httpReq.Host`. Scheme is not rebuilt. `pkg/appsec/query.go`
- Query tests do not assert `X-Crowdsec-Appsec-Uri`. `pkg/appsec/zzz_query_test.go`
- Captcha-gate spec: Secure when TLS **or** Traefik-left proto equals `https`. Scenario "Connection TLS sets Secure" does not mention an explicit proto `http`. `openspec/specs/core_plugin_middleware_captcha-gate/spec.md`
- Usage packet: set Secure from TLS or proto `https`; do not copy GetRemoteIP hop trust into captcha. `knowledge/devdocs/core_plugin_middleware_captcha-gate.md`
- AppSec client spec does not freeze `X-Crowdsec-Appsec-Uri` shape. `openspec/specs/core_plugin_appsec_client/spec.md`
- Bot-detection spec relays `__crowdsec_challenge` as AppSec sent it; this plugin does not parse that cookie. `openspec/specs/core_plugin_appsec_bot-detection/spec.md` `knowledge/devdocs/core_plugin_appsec.md`
- Real e2e asserts `crowdsec_captcha_gate=` on solve and `__crowdsec_challenge` presence on bot-detection. Neither asserts `Secure`. Traefik URL is `http://localhost:8000`. `tests/e2e/real/captcha.Tests.ps1` `tests/e2e/real/appsec.Tests.ps1`
- Mock AppSec returns `__crowdsec_challenge=e2e; Path=/; HttpOnly` (no Secure). `tests/e2e/mock/mocklapi/main.go`
- Dual-cookie Secure e2e (TLS / `X-Forwarded-Proto`, both cookie names) — not found
- New leaf package for the wrapper — not found

## Desired
- Move the inbound-request wrapper into a new leaf package that imports neither bouncer, captcha, nor appsec. Constructor owns scheme. Callers do not assign scheme later. Do not mutate the live `*http.Request`.
- Scheme: trimmed `X-Forwarded-Proto` whole-value EqualFold `http` or `https` wins; else TLS non-nil → `https`, else `http`. Not a set proto: `wss`, empty, `https,http`, `Forwarded`, `Front-End-Https`, `X-Forwarded-Protocol`, `X-Scheme`, `URL.Scheme`.
- Bouncer fills the wrapper once after GetRemoteIP. Captcha and AppSec take that value instead of `*http.Request` plus a parallel remoteIP string.
- Captcha gate cookie Secure iff that scheme is `https`. Captcha must not read proto or TLS. Proto `http` with TLS set → not Secure.
- AppSec `X-Crowdsec-Appsec-Uri` is absolute: that scheme, `Request.Host` when `URL.Host` is empty, path and query preserved. Not from `URL.Scheme`.
- One real end-to-end test forges requests with and without TLS, using `X-Forwarded-Proto`, and asserts Secure on `crowdsec_captcha_gate` and `__crowdsec_challenge`.

## Affected
- `pkg/bouncer/clientrequest.go` (move)
- `pkg/bouncer/bouncer.go` and bouncer tests that build `clientRequest`
- `pkg/captcha/gate.go` `pkg/captcha/captcha.go` and captcha tests that pass a bare `*http.Request`
- `pkg/appsec/query.go` and AppSec tests that call `Query` with `*http.Request`
- `openspec/specs/core_plugin_middleware_captcha-gate/spec.md` (Secure owner becomes shared scheme; proto `http` + TLS)
- `knowledge/devdocs/core_plugin_middleware_captcha-gate.md` `knowledge/devdocs/core_plugin_appsec.md`
- new leaf package under `pkg/` (name not in the ask)
- a real e2e that asserts both cookies' Secure flag

## Out of scope
- Changing GetRemoteIP hop walking
- Trusting `URL.Scheme`
- Copying raw `wss` into the URI
- Re-deriving hop trust inside captcha (`forwardedHeadersTrustedIps` / `ForwardedHeadersInsecure`)
- Writing scheme onto the live `http.Request`
- Comma-split proto, RFC 7239 `Forwarded`, vendor proto aliases
- Gate HMAC, bind-IP, grace, other cookie attributes (HttpOnly, SameSite, Path, Domain, name)
- Parsing `__crowdsec_challenge` in this plugin
- Changing AppSec `X-Crowdsec-Appsec-Host` except as needed to fill URI host from `Request.Host` when `URL.Host` is empty
- Captcha redirect target (`r.URL.String()`) and custom-resource path checks

## Unknowns
- Leaf package name (ask says "a new leaf package", no identifier).
- Where the dual-cookie e2e lives: Go httptest through the plugin, `tests/e2e/real` against live CrowdSec 1.8, or the mock suite. Mock does not implement CrowdSec's scheme check; real e2e talks HTTP to Traefik (`TLS == nil`) unless an HTTPS entrypoint is added.
- Whether CrowdSec 1.8 `pkg/appsec/challenge` still keys Secure on `request.URL.Scheme == "https"` (vendor, not in this tree). Research notes document `X-Crowdsec-Appsec-Uri` as "Original URI" only. `knowledge/research/ext_crowdsec_appsec_protocol/`
- URI host when both `URL.Host` and `Request.Host` are set; ask only names the empty-`URL.Host` case.
- Captcha signatures that take only `*http.Request` (`IsCustomResourceRequest`, `IsCaptchaFormPost`, `WriteSolvedRedirect`, `gateCookieValue`) — ask named "instead of a bare `*http.Request` plus a parallel remoteIP string"; those have no parallel IP.

## Tensions
- Live captcha-gate spec and usage packet: Secure is TLS **or** proto `https`, decided inside `setGateCookie` from `r` alone. This ask: one shared scheme; proto exact `http`/`https` wins over TLS; captcha must not read proto or TLS. `openspec/specs/core_plugin_middleware_captcha-gate/spec.md`
- Archived explore for captcha-gate Secure: "Do not put scheme on `clientRequest`." This ask moves that wrapper out of bouncer and puts scheme on it. `devstate/2026/09/2026-09-18-captcha-gate-cookie-secure-forwarded-https/explore.md`
- Spec scenario "Connection TLS sets Secure" has no proto. This ask: explicit proto `http` with TLS set → not Secure. Dest tests would pass today's OR and fail that new case. `pkg/captcha/zzz_gate_test.go`
- Dest already matches the previous ticket's OR (no hop re-check). This ask keeps "do not re-check hop trust" and replaces the OR with proto-wins-then-TLS.
