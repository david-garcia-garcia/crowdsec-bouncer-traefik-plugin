# Requirement
IssueKey: 2026-09-06-captcha-handler-hardening

## Problem
`pkg/captcha` handles the captcha page, provider verify, and grace-period cache in one flow (`New` → `ServeHTTP` → `Validate`/`Check`). Five defects: (1) successful verify always 302s even when grace cache write fails → solve loop; (2) empty template path passes validation, `New` discards load error, nil template panics on serve; (3) siteverify omits `remoteip`; (4) transport/JSON errors return bare 400 instead of captcha retry UX; (5) no unit tests for these paths.

## Current (code)
- `pkg/captcha/captcha.go:96-103` — after valid verify, `cacheClient.Set` then unconditional 302; no write success check.
- `pkg/cache/cache.go:156-159` — Redis `set` logs error and returns void; caller cannot observe failure.
- `pkg/cache/cache.go:233-236` — `Client.Set` is void; delegates to backend without error return.
- `pkg/captcha/captcha.go:121-125` — `Check` discards `Get` error via `_`.
- `pkg/configuration/configuration.go:316-327` — template load only when `CaptchaFilePath != ""`; provider set without path skips template validation.
- `pkg/captcha/captcha.go:78-79` — `GetTemplate` error discarded in `New`.
- `pkg/captcha/captcha.go:109-114` — `c.template.Execute` with no nil guard.
- `pkg/configuration/configuration.go:464-479` — `validateCaptcha` does not require template path when provider is set.
- `pkg/captcha/captcha.go:143-146` — siteverify POST body is `secret` + `response` only.
- `pkg/bouncer/bouncer.go:287` — `ServeHTTP` receives `req.remoteIP` but `Validate(r)` does not take IP.
- `pkg/captcha/captcha.go:90-94` — any `Validate` error → HTTP 400 empty body.
- `pkg/captcha/captcha.go:146-162` — PostForm and JSON decode errors propagate as `Validate` errors.
- `pkg/captcha/captcha.go:105-117` — `success: false` correctly re-renders captcha page (200).
- not found — `pkg/captcha/*_test.go`
- `tests/e2e/real/captcha.Tests.ps1:43-50` — e2e asserts captcha HTML marker only.

## Desired
- Make grace-period cache write observable; on failure do not 302 — log and re-render captcha or return 503 with operator signal.
- Require loadable captcha template when provider is set; `Client.New` returns `GetTemplate` error; no nil template at runtime.
- Pass bouncer-resolved client IP as `remoteip` on siteverify; thread `remoteIP` from `ServeHTTP` into `Validate`.
- Treat provider transport and JSON parse errors like failed verification: log, serve captcha HTML (200); no bare 400 for retryable failures.
- Add `pkg/captcha/captcha_test.go` covering Validate (success/failure/content-type/network), ServeHTTP grace and failed cache write, New (built-in/custom/empty/unreadable template), siteverify body includes `remoteip`.

## Affected
- `pkg/captcha/captcha.go` — primary handler changes.
- `pkg/cache/cache.go` — likely needs `Set` error return or test stub seam for observable writes.
- `pkg/configuration/configuration.go` — template required when provider set.
- `pkg/bouncer/bouncer.go` — already passes `remoteIP` to `ServeHTTP`; may need signature change on `Validate`.
- new `pkg/captcha/captcha_test.go`

## Out of scope
- In-memory cache mode where `Set` cannot fail (still test Redis/stub failure path).
- X-Forwarded-For trust (`pkg/ip`).
- SSRF via operator `CaptchaCustomValidateURL`.
- Template file deleted after successful startup.
- Full browser widget e2e.

## Unknowns
- Whether `cache.Client.Set` should return error (API change) vs inject a test double — explore/propose decides minimal seam.
- Exact HTTP status on cache write failure (503 vs 200 re-render) — ticket allows either with operator signal.

## Tensions
- Ticket asks for observable `Set`; current `cache.Client.Set` is void by design — may require cache API change or captcha-local wrapper.
- Config validates template only when path non-empty (`configuration.go:323-327`); ticket wants require when provider set — validation gap vs backward compat for deployments with empty path today.
- `success: false` re-show (200) is correct UX; transport/JSON errors currently 400 — ticket distinguishes these; implement must not break the working false-success path.
