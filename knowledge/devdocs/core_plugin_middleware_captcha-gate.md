# Captcha gate cookie

## Language

**Captcha gate cookie**:
HttpOnly `crowdsec_captcha_gate` issued after Validate Pass. Payload is versioned, HMAC-SHA256 signed with `captchaGateSecret`. Grace is not stored in the connection cache.
_Avoid_: `{ip}_captcha`, `CaptchaDoneValue`, reusing `CaptchaSecretKey` for the gate MAC, leftover `bouncerCaptchaGateSecret`

## Overview

Configure `captchaGateSecret` (or file) when `captchaEnabled` is true. Optional `captchaGateBindIp` (default true) ties the cookie to `req.RemoteIP()` as `clientrequest.New` stored it (`core_plugin_clientrequest_inbound-request.md`).

## How to use

- Validation: `pkg/captcha.Client.Check(req)` reads the cookie only; stale cache grace keys are ignored.
- After solve: `ServeHTTP` sets the gate cookie then 302; no cache write.
- Cookie-only mode: set `captchaGateBindIp` false; payload uses bind flag `0` and empty IP segment.
- Set `Secure` iff `req.Scheme()` is `https`. Captcha MUST NOT read `X-Forwarded-Proto` or `Request.TLS`. Do not copy `GetRemoteIP` hop trust into captcha. Scheme owner: `core_plugin_clientrequest_inbound-request.md`.

## Key files

- `pkg/captcha/gate.go`
- `pkg/captcha/captcha.go`
- `pkg/clientrequest/request.go`
- `pkg/configuration/configuration.go`

## Gotchas

- IPv4 addresses in the payload use `SplitN` parsing (dots in IP are allowed).
- Rotating `captchaGateSecret` invalidates outstanding gate cookies.
- Captcha does not read proto or TLS. `wss`, `Forwarded`, vendor proto aliases, and `URL.Scheme` are not a set proto at `New`; they do not become scheme `https` unless TLS is set.
