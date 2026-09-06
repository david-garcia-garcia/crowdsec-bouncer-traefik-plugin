# Requirement
IssueKey: 2026-09-06-upstream-353-captcha-session-cookie

## Problem
After a captcha is solved, grace-period bypass is keyed only on client IP. Users behind the same NAT inherit access when one peer solves; a solver can reuse the same IP with automation for the full `CaptchaGracePeriodSeconds` window.

## Current (code)
- `pkg/captcha/captcha.go:98` — on valid solve, `cacheClient.Set(remoteIP+"_captcha", CaptchaDoneValue, gracePeriodSeconds)`; no `Set-Cookie`.
- `pkg/captcha/captcha.go:121-125` — `Check(remoteIP)` reads `remoteIP+"_captcha"` only; no request cookie, user-agent, or protocol check.
- `pkg/captcha/captcha.go:89` — `ServeHTTP` accepts `remoteIP string`; full `*http.Request` is available but not used for session binding on check/store.
- `pkg/bouncer/bouncer.go:282-287` — captcha path calls `Check(req.remoteIP)` and `ServeHTTP(..., req.remoteIP)`; no session token passed.
- `pkg/cache/cache.go:22-23` — `CaptchaDoneValue` is a plain `"d"` marker; no per-session payload.
- `pkg/appsec/query.go:68,138` — forwards `UserCookies` and `User-Agent` to AppSec; separate relay from plugin-native captcha grace.
- `pkg/captcha/` — no `*_test.go` for solve/check/session behavior.
- `pkg/bouncer/bouncer_test.go:100-109` — method-based captcha vs ban only; no cookie/session coverage.

## Desired
- On captcha solve, issue a session cookie and store grace state bound to IP **and** that cookie (Cloudflare-like); on later requests, require a matching cookie or treat captcha as unsolved.
- Per upstream UPD, optionally bind the same session to user-agent and HTTP protocol (`ProtoMajor`) so copied cookies in another client stack do not pass.
- Add tests covering shared-IP isolation and post-solve check with/without the session cookie.

## Affected
- `pkg/captcha/captcha.go` (store, check, cookie response)
- `pkg/bouncer/bouncer.go` (pass request context into captcha check/serve)
- New or extended tests under `pkg/captcha/` and/or `pkg/bouncer/`

## Out of scope
- AppSec bot-detection challenge cookies in `pkg/appsec` (different remediation path).
- New public Traefik config keys unless explore/propose shows they are required for cookie name/TTL.
- Claiming foolproof bot defense (upstream acknowledges limitations).
- Changing captcha provider integration (`Validate` / siteverify) beyond session binding after success.

## Unknowns
- Cookie name, `Secure`/`HttpOnly`/`SameSite`, and path defaults for Traefik middleware.
- Whether v1 ships IP+cookie only or also UA+protocol binding from the UPD.
- Cache key shape and behavior when grace entries already exist for IP-only keys (upgrade/migration).

## Tensions
- Primary upstream ask is IP+cookie; UPD adds UA+protocol as extra hardening — scope for first implementation vs follow-up.
- Assessment recommends fix on our fork; upstream issue is feature request, not merged upstream behavior to mirror verbatim.
