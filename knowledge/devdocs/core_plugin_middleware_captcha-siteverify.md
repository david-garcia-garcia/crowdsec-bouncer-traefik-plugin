# Captcha siteverify

## Language

**Siteverify**:
The provider HTTP POST `Validate` makes to `infoProvider.validate` with form `secret` and `response`. Built-in URLs are hCaptcha / reCAPTCHA / Turnstile; custom uses `CaptchaCustomValidateURL`.
_Avoid_: captcha gate cookie, `CaptchaCustomJsURL`, treating vendor JSON `success` as the HTTP status

**Successful provider verify**:
A received siteverify response with status 200–299 inclusive, `Content-Type` prefix `application/json`, and decoded JSON `success: true`. Only this return lets `ServeHTTP` mint `crowdsec_captcha_gate` and 302.
_Avoid_: HTTP 500 with `{"success":true}`, 200-only, decoding `success` before the status check

**Failed verify**:
`Validate` returns `(false, nil)`. `ServeHTTP` re-renders the challenge at 200. Distinct from a `Validate` error (bare 400).
_Avoid_: treating non-2xx as `(false, err)`, transport `PostForm` error

## Overview

`Validate` owns whether a received siteverify HTTP response may count as a successful provider verify. Cookie mint and first-solve 302 stay on `core_plugin_middleware_captcha-gate`.

## How to use

- After `PostForm` returns a response, require status 200–299 before Content-Type or decode.
- Non-2xx: return `(false, nil)`. Debug the status. Do not inspect Content-Type. Do not decode `success`.
- After 2xx: dest `Content-Type` prefix `application/json` then decoded `success` still decide.
- Same path for every provider, including custom (`infoProvider.validate`).
- Do not add `remoteip` here. Do not drain the body beyond the existing `defer` close.
- Prove HTTP 500 + JSON `{"success":true}` does not mint the gate cookie or 302 (`pkg/captcha/` `zzz_*_test.go`).

## Key files

- `pkg/captcha/captcha.go` (`Validate`)

## Gotchas

- Vendor docs define the verdict as JSON `success`, not HTTP status. Failed tokens are still a 2xx JSON body. The 2xx gate is ours; it does not reject those documented failure bodies.
- Transport `PostForm` `err != nil` stays `(false, err)` → 400. That is not this unit (PR #28).
- Do not fold the status rule into `core_plugin_middleware_captcha-gate`.
