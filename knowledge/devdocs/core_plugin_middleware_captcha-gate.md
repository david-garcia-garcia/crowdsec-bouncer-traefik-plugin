# Captcha gate cookie

## Language

**Captcha gate cookie**:
HttpOnly `crowdsec_captcha_gate` issued after provider siteverify succeeds. Payload is versioned, HMAC-SHA256 signed with `bouncerCaptchaGateSecret`. Grace is not stored in the connection cache.
_Avoid_: `{ip}_captcha`, `CaptchaDoneValue`, reusing `BouncerCaptchaSecretKey` for the gate MAC, captchaGateSecret

## Overview

Configure `bouncerCaptchaGateSecret` (or file) when `bouncerCaptchaProvider` is set. Optional `bouncerCaptchaGateBindIP` (default true) ties the cookie to `clientRequest.remoteIP` after ServeHTTP has canonicalized a successful parse.

## How to use

- Validation: `pkg/captcha.Client.Check(r, remoteIP)` reads the cookie only; stale cache grace keys are ignored.
- After solve: `ServeHTTP` sets the gate cookie then 302; no cache write.
- Cookie-only mode: set `bouncerCaptchaGateBindIP` false; payload uses bind flag `0` and empty IP segment.
- Set `Secure` when the request has TLS or Traefik-left `X-Forwarded-Proto` is `https` (trim, case-insensitive, whole value). Do not copy `GetRemoteIP` hop trust into captcha.

## Key files

- `pkg/captcha/gate.go`
- `pkg/captcha/captcha.go`
- `pkg/configuration/configuration.go`

## Gotchas

- IPv4 addresses in the payload use `SplitN` parsing (dots in IP are allowed).
- Rotating `bouncerCaptchaGateSecret` invalidates outstanding gate cookies.
- `wss`, `Forwarded`, vendor proto aliases, and `r.URL.Scheme` do not set `Secure`. Traefik already sanitized `X-Forwarded-Proto`.
