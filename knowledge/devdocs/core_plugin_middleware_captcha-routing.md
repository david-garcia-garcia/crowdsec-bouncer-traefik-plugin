# Captcha request routing

## Language

**Captcha request routing**:
The captcha-kind branch of `handleRemediationServeHTTP` after the gate cookie: custom-resource passthrough, solved-form redirect, origin, or challenge.
_Avoid_: captcha gate cookie, `{ip}_captcha`, prefix bypass

**Solved-form POST**:
A POST whose provider response field is non-empty after the same reader Validate uses. Not a GET with a query token.
_Avoid_: ordinary POST, query-only token, first-solve Validate

**Custom challenge resource**:
A same-origin browser widget path stored from `CaptchaCustomJsURL` and optional `captchaCustomChallengeUrl` on a custom provider. Matched exact path only.
_Avoid_: `CaptchaCustomValidateURL`, prefix match, built-in CDN URL

**captchaCustomChallengeUrl**:
Optional Config field naming a second browser widget path. Empty means the JsURL path only. Not a required custom field.
_Avoid_: `CaptchaCustomValidateURL`, template `ChallengeURL`

## Overview

`handleRemediationServeHTTP` routes captcha-kind requests after cookie grace and first-solve 302. Cookie mint stays on `core_plugin_middleware_captcha-gate`.

## How to use

- Sequence captcha + Valid as: custom-resource path → Check-true form POST 302 → Check-true origin → `captcha.ServeHTTP` (HEAD included). Else ban.
- Detect form POST with `IsCaptchaFormPost` (reuses `captchaResponseFromRequest`). Do not add a second body reader.
- After Check, call `WriteSolvedRedirect`: `302 Found` to `req.URL.String()`, set the remediation header to `solved-captcha` when configured. Do not remint the gate cookie. Do not call siteverify.
- Match custom assets with `IsCustomResourceRequest`. At `Client.New` (custom provider only), `url.Parse` `CaptchaCustomJsURL` and optional `captchaCustomChallengeUrl`; keep each path that is non-empty and starts with `/`. Compare to `req.URL.Path`. Ignore host and query. Never `CaptchaCustomValidateURL`. Never a prefix.
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
