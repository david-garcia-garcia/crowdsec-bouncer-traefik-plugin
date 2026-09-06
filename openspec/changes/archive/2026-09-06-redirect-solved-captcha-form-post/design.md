## Context

See proposal.md — Why. Today `handleRemediationServeHTTP` on captcha + `Check(remoteIP)` calls `handleNextServeHTTP` with the original method. `captcha.Client.ServeHTTP` already redirects with `StatusFound` after a successful verify. The grace key owner is `clientRequest.remoteIP` (`devstate/explore.md`). Provider response field names live on `captcha.Client` (`infoProvider.response`). `ParseForm` / `FormValue` consume `req.Body`; the unsolved path never forwards, so that consume is safe there only.

## Goals / Non-Goals

**Goals:**
- Same redirect as first successful verify for a captcha form POST after grace.
- Ordinary POSTs after solve still reach origin with body intact.
- One owner for “is this a captcha form POST” and one owner for the solved redirect response.

**Non-Goals:**
- Changing `captcha.html` or adding a dedicated captcha URL.
- Re-verifying with the provider on the already-solved path.
- Refreshing grace TTL on the second submit.
- Captcha handler hardening unrelated to this POST (network errors, empty path, AppSec-mode init).

## Decisions

1. **`captcha.Client` detects the form POST.** It already holds the configured response field. Bouncer MUST NOT hard-code `h-captcha-response` or `CaptchaCustomResponse`. Alternative: inspect every POST in bouncer — rejected; field name is captcha’s job.

2. **`captcha.Client` owns the solved redirect.** Extract the existing success response (remediation header `solved-captcha` when configured, `http.Redirect` `StatusFound` to `r.URL.String()`) so first verify and grace intercept stay symmetrical. Grace intercept does not `Set` the cache again. Alternative: duplicate redirect in bouncer — rejected (`skill:sbs-dev-commandments:One job, one owner`).

3. **Inspect then restore Body when not intercepting.** For POST, read enough to see the configured field, then if the field is absent restore `Body` (and `ContentLength`) before `handleNextServeHTTP`. If intercepting, the body may stay consumed. Do not call `FormValue` then forward. Alternative: redirect every POST during grace — rejected; origin forms after solve would break.

4. **Intercept before `handleNextServeHTTP`.** Duplicate captcha POSTs MUST NOT hit AppSec or origin (first solve never did). Identity: `Check(req.remoteIP)` only.

5. **Tests:** in-memory cache + `httptest` next. No Laravel. Cover hcaptcha and custom field names; grace captcha POST → 302 and next not called; grace ordinary POST → next called with body.

## Risks / Trade-offs

- [ParseForm empties origin POST] → restore Body when not intercepting; test the body round-trip.
- [False intercept if an origin form reuses a captcha field name] → accept; field names are provider-specific. Document in usage if a packet is written later.
- [302 vs 303] → keep `StatusFound` to match first verify, not a new status.

## Migration Plan

Plugin version bump. No YAML keys. Rollback is the previous tag (second-tab POST reaches origin again).

## Open Questions

None. Assumed proceed policies live on `devstate/explore.md`.
