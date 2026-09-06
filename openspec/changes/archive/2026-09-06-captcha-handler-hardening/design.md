## Context

See proposal.md — Why. On `master`, `pkg/captcha.Client.ServeHTTP` always 302s after valid verify regardless of `cacheClient.Set` outcome; `Set` is void and Redis errors are logged inside `pkg/cache`. `Validate` returns errors for transport/JSON failures and `ServeHTTP` maps any error to HTTP 400. `Client.New` discards `GetTemplate` errors. `ValidateParams` loads the captcha template only when `CaptchaFilePath != ""`. The bouncer already resolves `remoteIP` via `pkg/ip` and passes it to `ServeHTTP` but not to `Validate`.

## Goals / Non-Goals

**Goals:**
- Observable grace cache write; no redirect until write succeeds.
- Startup fail on missing/unreadable captcha template when a provider is configured.
- Siteverify includes bouncer-resolved `remoteip`.
- Retryable provider failures reuse the captcha page UX (200), same as `success: false`.
- Unit tests with httptest siteverify stub and injectable cache failure.

**Non-Goals:**
- In-memory cache failure simulation beyond stub tests (memory `Set` always succeeds).
- X-Forwarded-For trust changes (`pkg/ip`).
- SSRF hardening for `CaptchaCustomValidateURL`.
- Template deleted after successful startup.
- Full browser widget e2e.

## Decisions

1. **`cache.Client.Set` returns `error`.** Propagate Redis writer errors; in-memory `localCache.set` returns nil. Existing callers that ignore the return keep today’s behavior. Alternative: captcha-local wrapper — rejected; explore chose minimal shared seam.

2. **Grace write failure → re-render captcha 200 + Error log.** Do not 302. Operator signal is the log line. Alternative: HTTP 503 — rejected; ticket allows either; 200 is less disruptive.

3. **Require loadable template when `CaptchaProvider != ""`.** Extend `validateCaptcha` / `ValidateParams` to require non-empty `CaptchaFilePath` and successful `GetTemplate`. **BREAKING** for deployments with provider but empty path. Alternative: lazy fail at first request — rejected; nil template panics today.

4. **`Client.New` returns `GetTemplate` error.** Remove `_` discard so constructor failure surfaces at init.

5. **Thread `remoteIP` into `Validate(r, remoteIP)`.** Add `remoteip` to siteverify POST for all built-in and custom providers using the siteverify contract. Reuse bouncer-resolved IP; do not re-parse headers in captcha.

6. **Retryable verify failures use sentinel or typed error.** `ServeHTTP` logs and re-renders captcha (200) for transport and JSON decode errors; keep `(false, nil)` for `success: false` and empty response field. Bare 400 only if a non-retryable malformed request remains (likely none after change).

7. **Unit tests in `pkg/captcha/captcha_test.go`.** Table-driven cases: Validate success/failure/content-type/network; ServeHTTP grace and failed cache write; New built-in/custom/empty/unreadable template; siteverify body includes `remoteip`.

## Risks / Trade-offs

- [Breaking empty template path] → validation error at startup with clear message; documented in proposal.
- [Set API change] → all call sites compile-check; only captcha checks the error today.
- [Yaegi] → signature change on `Validate` stays within existing packages; no new root exports.

## Migration Plan

Plugin version bump. Operators with captcha provider must set a valid `captchaFilePath`. No config key rename. Rollback: previous tag restores void `Set` and optional template path.
