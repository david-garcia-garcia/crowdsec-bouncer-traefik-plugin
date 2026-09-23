# Captcha request routing

## Language

**Captcha request routing**:
The captcha-kind branch of `handleRemediationServeHTTP` after the gate cookie: custom-resource passthrough, solved-form redirect, origin, or challenge.
_Avoid_: captcha gate cookie, `{ip}_captcha`, prefix bypass

**Solved-form POST**:
A POST whose provider response field is non-empty in a body of at most `captchaFormMaxBytes` (64KiB), read by `IsCaptchaFormPost`. Not a GET with a query token, and not an over-cap upload that happens to contain the field name.
_Avoid_: ordinary POST, query-only token, first-solve Validate

**First-verify reader**:
`captchaResponseFromRequest`, used only by `Validate` on a request the plugin answers itself. It may `ParseForm` and truncate at 1MiB because that request is never forwarded.
_Avoid_: calling it from routing, sharing it with `IsCaptchaFormPost`

**Custom challenge resource**:
A same-origin browser widget path stored from `CaptchaCustomJsURL` and optional `captchaCustomChallengeUrl` on a custom provider. Matched exact path only.
_Avoid_: `CaptchaCustomValidateURL`, prefix match, built-in CDN URL

**captchaCustomChallengeUrl**:
Optional Config field naming a second browser widget path, and the source of template `ChallengeURL`. Empty means the JsURL path only. Not a required custom field.
_Avoid_: `CaptchaCustomValidateURL`, the bundled default `captcha.html`

## Overview

`handleRemediationServeHTTP` routes captcha-kind requests after cookie grace and first-solve 302. Cookie mint stays on `core_plugin_middleware_captcha-gate`.

## How to use

- Load the published captcha Client. Empty or `!Valid` remediates as ban. Do not construct a local client on the request path or in bounce-only `New`.
- Pass this router's `remediationCustomHeader` into `ServeHTTP` and `WriteSolvedRedirect`. Do not store the header on Client.
- Sequence a loaded Valid client as: custom-resource path → Check-true form POST 302 → Check-true origin → `captcha.ServeHTTP` (HEAD included). Else ban.
- HEAD under a captcha remediation gets the challenge page, never the ban page. That is ratified; do not "fix" it back to ban. A HEAD on a custom-resource path still reaches origin.
- Detect form POST with `IsCaptchaFormPost`. It is a reader of its own, not `captchaResponseFromRequest`: routing may still forward the request, so it caps at 64KiB, reads urlencoded and multipart, answers from `PostForm` when the form was already parsed, and restores `Body` plus `ContentLength` when it answers no. Keep the two callers apart.
- After Check, call `WriteSolvedRedirect`: `302 Found` to `req.URL.String()`, set the remediation header to `solved-captcha` when configured. Do not remint the gate cookie. Do not call siteverify.
- Match custom assets with `IsCustomResourceRequest`. `configuration.CustomCaptchaResourcePath` is the one owner of which configured value names a browser path; `Client.New` calls it for `CaptchaCustomJsURL` and optional `captchaCustomChallengeUrl` (custom provider only) and compares the stored paths to `req.URL.Path`. Ignore host and query. Never `CaptchaCustomValidateURL`. Never a prefix.
- Render the endpoint through template `ChallengeURL` (execute map sibling of `FrontendJS`). Captcha templates use `{{` / `}}`, unlike the ban template's `[[` / `]]`. Wire it in `examples/custom-captcha`, not in the bundled default `captcha.html`.
- Past-captcha is `Check(req.Request, req.remoteIP)` only — the HMAC gate cookie. Do not read or write cache grace keys, and do not reintroduce an IP-keyed grace cache.
- Passthrough and Check-true ordinary requests call `handleNextServeHTTP`. Ban never passthrough.

## Key files

- `pkg/bouncer/bouncer.go`
- `pkg/captcha/captcha.go`
- `pkg/configuration/configuration.go`

## Gotchas

- Built-in provider CDN URLs are not a match set, and their `ChallengeURL` renders empty.
- Empty `bouncerCaptchaCustomChallengeUrl` keeps JsURL-path only; it is not a required custom field. A non-empty custom-provider value that names no absolute path is rejected by `validateEnabledCaptchaSettings` — that is master's owner, not a rival `validateConfiguredCaptcha`.
- A captcha token hidden inside an over-cap POST is deliberately missed; keeping the upload body intact for origin matters more.
- Yaegi v0.16: do not put `atomic.Pointer[T]` on a struct consumed from another package.
