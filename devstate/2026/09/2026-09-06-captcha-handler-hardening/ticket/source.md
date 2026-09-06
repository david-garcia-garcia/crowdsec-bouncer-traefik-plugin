# Captcha handler swallows cache and template failures, omits siteverify remoteip, and has no unit tests

slug: captcha-handler-hardening
component: captcha
severity: bug

## Problem
`pkg/captcha` is the per-request captcha page, provider verify, and grace-period cache. Several defects share that one flow (`New` → `ServeHTTP` → `Validate`/`Check`) and should land in one change with `pkg/captcha/captcha_test.go`.

1. After a successful provider verify, `ServeHTTP` always 302s even when the grace-period cache write fails (Redis). The next GET still shows captcha — a solve loop.
2. Empty `captchaFilePath` passes validation; `Client.New` discards `GetTemplate` error; first serve panics on nil template.
3. Siteverify POST sends only `secret` and `response`. Built-in providers accept `remoteip`; a token captured elsewhere can be replayed.
4. Provider transport or JSON errors return a bare HTTP 400. `success: false` re-shows the captcha page. The user sees a broken site instead of a retry.
5. There is no `pkg/captcha/*_test.go`. e2e only asserts the captcha HTML marker, not verify or grace.

## Desired
- `Set` must be observable. On grace-period write failure, do not 302; log and re-render captcha or return 503 with an operator-facing signal.
- Require a loadable captcha template when a provider is set. `Client.New` returns `GetTemplate` error. Do not start with a nil template.
- Pass the bouncer-resolved client IP as `remoteip` on siteverify (built-in and custom providers that use that contract). Thread `remoteIP` from `ServeHTTP` into `Validate`.
- Treat provider transport and JSON parse errors like failed verification: log, serve captcha HTML (200). Do not use a bare 400 for retryable verify failure.
- Add `pkg/captcha/captcha_test.go`: Validate httptest stub (success/failure/content-type/network); ServeHTTP grace period and failed cache write; New built-in vs custom vs empty/unreadable template; siteverify body includes `remoteip`.

## Out of scope
- In-memory cache mode where `Set` cannot fail (still test the Redis/stub failure path)
- X-Forwarded-For trust (`pkg/ip`)
- SSRF via operator `CaptchaCustomValidateURL`
- Template file deleted after successful startup
- Full browser widget e2e

## Grouped findings
captcha-solve-loop-on-cache-failure, nil-template-empty-captcha-path, siteverify-missing-remoteip, validate-network-error-bare-400, no-unit-tests-core-paths

These are one `pkg/captcha` handler change plus unit tests. Do not open separate PRs.
