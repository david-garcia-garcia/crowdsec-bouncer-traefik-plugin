# Explore
IssueKey: 2026-09-06-captcha-handler-hardening

## Concepts
- Captcha flow: `Bouncer.handleRemediationServeHTTP` → `Check` (grace cache) → `ServeHTTP` (validate POST or render page) → provider siteverify → grace cache `Set` on success → 302.
- `remoteIP` is already resolved by the bouncer (`clientRequest.remoteIP` from `pkg/ip`); captcha receives it in `ServeHTTP` but not in `Validate`.
- `cache.Client.Set` is void; Redis errors are logged inside `redisCache.set` and swallowed. Captcha cannot detect write failure today.
- Config loads template only when `CaptchaFilePath != ""`; provider without path leaves nil template in `Client.New`.
- `Validate` returns `(false, err)` for network/JSON errors; `ServeHTTP` maps any error to bare 400. `success: false` returns `(false, nil)` and correctly re-renders captcha.

## Decisions
- Change `cache.Client.Set` (and internal `cacheInterface.set`) to return `error`, propagating Redis writer errors. Existing callers that do not need the result ignore it; captcha checks before redirect. In-memory `localCache.set` returns nil always.
- On grace-period write failure after successful verify: log at Error, re-render captcha page (200) — do not 302. Matches ticket option and avoids user-visible outage; operator signal is the log line.
- Require loadable captcha template when `CaptchaProvider != ""`: extend `validateCaptcha` (or the provider block in `ValidateConfiguration`) to require non-empty `CaptchaFilePath` and successful `GetTemplate`.
- `Client.New` must return `GetTemplate` error; remove `_` discard.
- Thread `remoteIP` into `Validate(r, remoteIP)`; add `remoteip` to siteverify POST body for all providers using that contract.
- Distinguish retryable verify failures (transport, JSON decode) from hard client errors: introduce a sentinel or typed error so `ServeHTTP` logs and re-renders captcha (200) for retryable cases; keep 400 only for non-retryable malformed requests if any remain (likely none after change).
- Unit tests in `pkg/captcha/captcha_test.go` with httptest stub for siteverify, injectable cache stub for Set failure, table-driven cases per ticket list.

## Open questions
- Q: Should `cache.Client.Set` return error (API change) or captcha use a test-only wrapper?
  Decision: assumed — change `Set` to return `error`; minimal surface, redis already has the error, other callers unchanged behavior when ignored.
  By: explore

- Q: HTTP status on grace cache write failure — 503 vs 200 re-render?
  Decision: assumed — re-render captcha 200 with Error log; less disruptive than 503; ticket allows either with operator signal.
  By: explore

- Q: Who owns client IP for siteverify `remoteip`?
  Decision: resolved — bouncer owns `req.remoteIP`; captcha reuses the value already passed to `ServeHTTP`; do not re-parse headers in captcha.
  By: explore

- Q: Backward compat for deployments with provider set but empty template path?
  Decision: assumed — breaking change accepted per ticket; validation fails at startup with clear error.
  By: explore
