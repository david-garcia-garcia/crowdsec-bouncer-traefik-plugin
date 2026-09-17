# Captcha request routing

## Overview

`handleRemediationServeHTTP` routes captcha-kind requests after cookie grace and first-solve 302. Cookie mint stays on `core_plugin_middleware_captcha-gate`.

## How to use

- Sequence captcha + Valid as: custom-resource path → Check-true form POST 302 → Check-true origin → `captcha.ServeHTTP` (HEAD included). Else ban.
- Detect form POST with `IsCaptchaFormPost` (reuses `captchaResponseFromRequest`). Do not add a second body reader.
- Match custom assets with `IsCustomResourceRequest` (exact path of `CaptchaCustomJsURL` and optional `captchaCustomChallengeUrl`). Never `CaptchaCustomValidateURL`. Never a prefix.
- Past-captcha is `Check(req.Request, req.remoteIP)` only. Do not read or write cache grace keys.
- Passthrough and Check-true ordinary requests call `handleNextServeHTTP`. Ban never passthrough.

## Key files

- `pkg/bouncer/bouncer.go`
- `pkg/captcha/captcha.go`
- `pkg/configuration/configuration.go`

## Gotchas

- Built-in provider CDN URLs are not a match set.
- Empty `captchaCustomChallengeUrl` keeps JsURL-path only; it is not a required custom field.
- Yaegi v0.16: do not put `atomic.Pointer[T]` on a struct consumed from another package.
