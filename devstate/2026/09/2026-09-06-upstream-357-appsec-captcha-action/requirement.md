# Requirement
IssueKey: 2026-09-06-upstream-357-appsec-captcha-action

## Problem
Upstream #357 requests AppSec JSON `action: captcha` support (read the response body, not only HTTP status). Local assessment finds parsing and relay code on `master` but no test proves `{"action":"captcha",...}` is handled like other structured AppSec remediations.

## Current (code)
- `pkg/appsec/query.go:27-31` — `ActionCaptcha` constant alongside allow, ban, challenge.
- `pkg/appsec/query.go:110-114,196-221` — capped body read and `parseResponse` unmarshals `action` from JSON envelope.
- `pkg/bouncer/bouncer.go:319-330` — `applyAppsecServeHTTP` special-cases ban and empty-body challenge; other non-allow actions (including captcha) fall through to `handleAppsecResponseServeHTTP`.
- `pkg/bouncer/bouncer.go:333-369` — `handleAppsecResponseServeHTTP` writes status, body, cookies, headers from the AppSec envelope.
- `pkg/appsec/query_test.go:210-225` — `Test_appsecQuery_challengeJSON` covers challenge parsing only; no captcha JSON case.
- `pkg/bouncer/bouncer_test.go:151-179` — challenge relay e2e; no captcha action relay case.
- `knowledge/devdocs/core_plugin_appsec.md:25-27` — documents AppSec `action: captcha` HTML relay vs `pkg/captcha` for LAPI/failure-action.

## Desired
- Add tests that assert AppSec JSON `{"action":"captcha",...}` parses in `pkg/appsec` and relays through the bouncer the same way as challenge (status, body, headers/cookies when present).
- Do not change product behavior unless a test cannot be honest without a one-line correctness fix.

## Affected
- `pkg/appsec/query_test.go`
- `pkg/bouncer/bouncer_test.go`

## Out of scope
- Upstream optional solved-captcha caching mode or config knob.
- `pkg/captcha` provider flow for LAPI remediations or AppSec failure-action captcha.
- New AppSec protocol fields beyond captcha action relay already in the envelope struct.

## Unknowns
- Whether production AppSec captcha envelopes always include `user_body_content` (empty body relay vs ban — challenge empty body currently bans in `applyAppsecServeHTTP`).

## Tensions
- Upstream ticket reads as missing feature; assessment says present-fixed-unproven — this run is test proof only (`recommended-action: add-tests`).
- AppSec `action: captcha` is HTML envelope relay, not `pkg/captcha` — tests must not assert hCaptcha/recaptcha/Turnstile provider behavior.
