# Captcha gate cookie

## Language

**Captcha gate cookie**:
HttpOnly `crowdsec_captcha_gate` issued after provider siteverify succeeds. Payload is versioned, HMAC-SHA256 signed with `captchaGateSecret`. Grace is not stored in the connection cache.
_Avoid_: `{ip}_captcha`, `CaptchaDoneValue`, reusing `CaptchaSecretKey` for the gate MAC

## Overview

Configure `captchaGateSecret` (or file) when `captchaProvider` is set. Optional `captchaGateBindIP` (default true) ties the cookie to `clientRequest.remoteIP` after ServeHTTP has canonicalized a successful parse.

## How to use

- Validation: `pkg/captcha.Client.Check(r, remoteIP)` reads the cookie only; stale cache grace keys are ignored.
- After solve: `ServeHTTP` sets the gate cookie then 302; no cache write.
- Cookie-only mode: set `captchaGateBindIP` false; payload uses bind flag `0` and empty IP segment.

## Key files

- `pkg/captcha/gate.go`
- `pkg/captcha/captcha.go`
- `pkg/configuration/configuration.go`

## Gotchas

- IPv4 addresses in the payload use `SplitN` parsing (dots in IP are allowed).
- Rotating `captchaGateSecret` invalidates outstanding gate cookies.
