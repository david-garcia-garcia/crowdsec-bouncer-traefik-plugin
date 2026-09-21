# Requirement
IssueKey: 2026-09-18-captcha-gate-cookie-secure-forwarded-https

## Problem
`setGateCookie` sets `Secure` only when `r.TLS != nil`. Traefik behind Cloudflare/ALB sees `TLS == nil` with `X-Forwarded-Proto: https`, so the captcha grace cookie is issued without `Secure` and can be sent on a same-host HTTP entrypoint.

## Current (code)
- `setGateCookie` builds `crowdsec_captcha_gate` with Path=/, HttpOnly, SameSite=Lax, and sets `Secure` only when `r.TLS != nil`. `pkg/captcha/gate.go`
- After siteverify succeeds, `ServeHTTP` calls `setGateCookie(rw, r, value, c.gracePeriodSeconds)` with no trusted-hop or insecure-forwarded inputs. `pkg/captcha/captcha.go`
- `captcha.Client` / `New` hold gate secret, bind-IP, grace, and template fields. They do not hold `BouncerForwardedTrustedIPs`, `BouncerForwardedInsecure`, or a proto trust helper. `pkg/captcha/captcha.go`
- `GetRemoteIP` honors the custom client-IP header only when `insecure` is true or `req.RemoteAddr` is in the trusted-hop pool; otherwise it returns the `RemoteAddr` host. `pkg/ip/checker.go`
- Captcha-gate spec requires Secure when the request is TLS. `openspec/specs/core_plugin_middleware_captcha-gate/spec.md`
- `TestHunt_gateCookieSecureWhenForwardedProtoHTTPS` — not found
- Solve-path test asserts the cookie name is set and does not assert `Secure`. `pkg/captcha/zzz_servehttp_test.go`

## Desired
- Set `Secure` when `r.TLS != nil` or the request is client-HTTPS via `X-Forwarded-Proto` from a hop the bouncer already trusts (same trusted-IP / `BouncerForwardedInsecure` model as `GetRemoteIP`).
- Include a regression test for that forwarded-https case.
- Bound the ask to this defect only.

## Affected
- `pkg/captcha/gate.go`
- `pkg/captcha/captcha.go` and bouncer wiring if trust inputs must reach `setGateCookie`
- captcha package tests (regression for the named hunt case)
- `openspec/specs/core_plugin_middleware_captcha-gate/spec.md` if Secure stays specified as TLS-only

## Out of scope
- Changing `GetRemoteIP` client-address selection
- Cloudflare- or ALB-specific proto parsers beyond the existing hop-trust model
- Other cookie attributes (HttpOnly, SameSite, Domain, Path, name)
- Gate HMAC, bind-IP, grace period, provider siteverify
- AppSec, LAPI, cache, Redis

## Unknowns
- How trust / `BouncerForwardedInsecure` reach `setGateCookie` (`Client` has no such fields today).
- Exact `X-Forwarded-Proto` parse (single value vs list, case). `GetRemoteIP` walks a client-IP header, not proto.
- Where the named hunt test should live; dest has no `TestHunt_*` functions.

## Tensions
- Ticket cites `pkg/captcha/gate.go:74-86`; dest `setGateCookie` is those lines and matches the TLS-only claim.
- Spec says Secure when the request is TLS; ticket also wants Secure for trusted forwarded https with `TLS == nil`.
- Ticket names `TestHunt_gateCookieSecureWhenForwardedProtoHTTPS` as proven FAIL; that test is not in this tree.
- Ticket says reuse the GetRemoteIP trust model for proto; that owner today decides client IP, not scheme.
