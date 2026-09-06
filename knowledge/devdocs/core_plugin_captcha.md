# Plugin-native captcha

## Language

**Captcha grace session**:
A solved plugin-native captcha for one client: cache entry `{remoteIP}_captcha_{token}` plus cookie `crowdsec_captcha` whose value is that token. The IP is GetRemoteIP’s address. TTL is `CaptchaGracePeriodSeconds`.
_Avoid_: IP-only `{ip}_captcha` allowlist, AppSec `__crowdsec_challenge`, AppSec JSON `action: captcha`

**crowdsec_captcha**:
The HttpOnly cookie this plugin sets on a valid solve. Path `/`, SameSite Lax, MaxAge = grace seconds, Secure when the request has TLS.
_Avoid_: `__crowdsec_challenge`, AppSec `user_cookies`

## Overview

`pkg/captcha.Client` owns the challenge page, provider siteverify, the session cookie, and the grace cache keys. The bouncer passes `req.Request` and `req.remoteIP`. Do not put captcha state on `clientRequest`.

## How to use

- Construct on the Bouncer from captcha config. Pass the isolated cache Client from the LAPI Client.
- `Check(r, remoteIP)` before serving the page. Missing, wrong, or other-IP cookie is unsolved. Leftover `{ip}_captcha` keys are unread.
- `ServeHTTP` on unsolved captcha. On valid solve it sets `crowdsec_captcha` and `{remoteIP}_captcha_{token}` then redirects.
- Do not parse `__crowdsec_challenge`. That is AppSec relay.

## Pattern snippet

```go
if b.captchaClient.Check(req.Request, req.remoteIP) {
	b.handleNextServeHTTP(rw, req)
	return
}
b.captchaClient.ServeHTTP(rw, req.Request, req.remoteIP)
```

## Key files

- `pkg/captcha/captcha.go`
- `pkg/bouncer/bouncer.go`
- `pkg/cache/cache.go` (`CaptchaDoneValue`)

## Gotchas

- Two NAT users on one IP need two tokens (two cache keys). One `{ip}_captcha` value would evict the first solver.
- After upgrade, IP-only grace keys do not pass Check; those clients re-solve.
- Cookie Secure is off when `r.TLS` is nil (HTTP labs, TLS terminated in front of Traefik).
