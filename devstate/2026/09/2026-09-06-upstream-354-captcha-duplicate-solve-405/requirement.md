# Requirement
IssueKey: 2026-09-06-upstream-354-captcha-duplicate-solve-405

## Problem
When a user opens two browser tabs on a captcha-gated page, solving captcha in tab one succeeds; submitting captcha from tab two returns HTTP 405 from the origin application (e.g. Laravel routes that only accept GET on that URL).

## Current (code)
- `captcha.html` POSTs back to the same URL via an empty `action` form (`captcha.html:296-299`).
- Captcha validation runs only in `captcha.Client.ServeHTTP`, which calls `Validate` on POST with a provider response field (`pkg/captcha/captcha.go:88-104`, `132-166`).
- After a successful verify, `ServeHTTP` sets grace cache key `remoteIP+"_captcha"` and redirects with `http.StatusFound` (`pkg/captcha/captcha.go:96-103`).
- `Bouncer.handleRemediationServeHTTP` skips captcha UI when `captchaClient.Check` is true and calls `handleNextServeHTTP`, relaying the request unchanged including method (`pkg/bouncer/bouncer.go:281-284`, `293-298`).
- A second-tab POST therefore reaches origin as POST after grace is set, while the first solve path would have redirected to GET.
- No unit or integration test covers duplicate-tab captcha POST after grace (`pkg/captcha/`: not found; `pkg/bouncer/bouncer_test.go`: method matrix only, no grace+POST case).

## Desired
When a captcha-remediated request already has a solved grace entry, intercept captcha POST submissions (requests carrying the provider response field) and redirect to the normal page instead of forwarding POST to origin — matching the behavior after the first successful verify.

## Affected
- `pkg/bouncer/bouncer.go` (`handleRemediationServeHTTP`)
- `pkg/captcha/captcha.go` (may need a helper to detect captcha POST vs ordinary POST)
- Tests under `pkg/bouncer/` and/or `pkg/captcha/`

## Out of scope
- Changing bundled `captcha.html` template or provider verify API calls.
- Broader captcha handler hardening from other bug-hunt items.
- Upstream PR submission to maxlerebourg/crowdsec-bouncer-traefik-plugin (fix lands on this fork only unless later directed).

## Unknowns
- Minimal unit-test seam to reproduce 405 without a full Laravel origin (assessment notes real app may be needed).
- Whether POST without captcha response field during grace should still pass through (ticket focuses on duplicate captcha submit).

## Tensions
- Ticket suggests intercepting all POSTs with `CaptchaCustomResponse`; custom provider field name is configurable (`pkg/configuration/configuration.go:118`) while built-in providers use provider-specific names (`pkg/captcha/captcha.go:41-59`) — fix must cover configured response field, not only the custom config key name.
- Grace path currently treats any method the same; ticket expectation is redirect semantics like first solve, not passthrough.
