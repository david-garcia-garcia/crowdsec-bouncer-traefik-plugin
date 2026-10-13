# Shared origin scheme (local)

IssueKey: 2026-09-30-origin-scheme
issueHost: local
issueRef: none

Build one shared origin scheme for the inbound request, and use it for both the captcha gate cookie Secure flag and the CrowdSec AppSec URI.

1. A new leaf package holds the inbound-request wrapper that today lives unexported in `pkg/bouncer/clientrequest.go`. The package imports neither bouncer, captcha, nor appsec. Bouncer fills it once in ServeHTTP after GetRemoteIP. Captcha and AppSec receive that value instead of a bare `*http.Request` plus a parallel remoteIP string.

2. The package owns the scheme rule and sets it in the constructor. Callers do not assign it later. Rule: if `X-Forwarded-Proto`, trimmed, matches the whole value `http` or `https` case-insensitively, that token is the scheme. No comma split. `wss`, empty, `https,http`, `Forwarded`, `Front-End-Https`, `X-Forwarded-Protocol`, `X-Scheme`, and `URL.Scheme` are not a set proto. When the proto is not an exact `http` or `https`, use `Request.TLS`: `https` when TLS is non-nil, otherwise `http`. Do not re-check `forwardedHeadersTrustedIps` or `ForwardedHeadersInsecure`. Do not write the scheme back onto the live `http.Request` that Traefik and next still hold.

3. Captcha sets the gate cookie Secure when that scheme is `https`. Captcha must not read `X-Forwarded-Proto` or `Request.TLS` itself. This replaces today's OR in `pkg/captcha/gate.go` `setGateCookie` (TLS or proto https). Explicit proto `http` with TLS set yields scheme `http` and a cookie that is not Secure.

4. AppSec `X-Crowdsec-Appsec-Uri` is an absolute client-facing URI: that scheme, `Request.Host` when `URL.Host` is empty, path and query preserved. AppSec must not take the scheme from `URL.Scheme`. Today `pkg/appsec/query.go` sends `httpReq.URL.String()`, which is path-only on a normal Traefik server request, so CrowdSec 1.8 omits Secure on the bot-detection challenge cookie (`pkg/appsec/challenge` in CrowdSec checks `request.URL.Scheme == "https"`).

5. A real end-to-end test forges requests with and without TLS, using `X-Forwarded-Proto`, and asserts the Secure flag on both cookies: the captcha gate cookie (`crowdsec_captcha_gate`) and the AppSec bot-detection challenge cookie (`__crowdsec_challenge`).

Out of scope for the ask (do not take them): changing GetRemoteIP hop walking; trusting URL.Scheme; copying raw wss into the URI; re-deriving hop trust inside captcha.
