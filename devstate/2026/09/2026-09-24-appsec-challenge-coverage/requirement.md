# Requirement
IssueKey: 2026-09-24-appsec-challenge-coverage

## Problem
This repo needs tests that prove AppSec challenge handling against upstream [maxlerebourg/crowdsec-bouncer-traefik-plugin#397](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397). That report describes two failures in the other plugin:

1. `action=challenge`, `http_status=200`, and empty or missing `user_body_content` is returned as HTTP 200 with an empty body. The CrowdSec challenge protocol requires fail-closed as the configured ban response. The challenge status must not be committed before that empty-body check.
2. When the response writer already has `Content-Security-Policy` and AppSec supplies its challenge CSP in `user_headers`, that plugin appends a second CSP (`Header().Add`). The protocol says AppSec-provided headers of the same name replace the existing header. Multiple `Set-Cookie` values must remain separate headers.

A passing test is the proof. Do not change production behavior unless a test shows the protocol behavior is absent. The delivery card must name https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397.

## Current (code)
- Empty-challenge fail-closed happens before the envelope writer: `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` (`ActionChallenge` and `UserBodyContent == ""` calls `handleBanServeHTTP` and returns; it does not call `handleAppsecResponseServeHTTP`).
- Operator ban page is `pkg/bouncer/bouncer.go` `handleBanServeHTTP` (remediation status, ban header, `banTemplate` when non-nil).
- Envelope writer copies `user_headers` by replacing the canonical key (`rw.Header()[http.CanonicalHeaderKey(name)] = values`), skips hop-by-hop and `Set-Cookie`, then `Header().Add("Set-Cookie", cookie)` per `user_cookies`: `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP`.
- Missing `user_body_content` on challenge is already tested as 403 + ban header, with a nil `banTemplate` so there is no ban-page body assertion, and there is no explicit empty-string `user_body_content` case: `pkg/bouncer/zzz_bouncer_test.go` `TestHandleNextServeHTTPEmptyChallengeBodyBans`.
- One challenge cookie is asserted via `Header().Get("Set-Cookie")`: `pkg/bouncer/zzz_bouncer_test.go` `TestHandleNextServeHTTPRelaysStructuredAppsecChallenge`. No test pre-sets `Content-Security-Policy` on the writer. No test asserts two `user_cookies` as two `Set-Cookie` values.
- Live spec already says empty challenge `user_body_content` is the operator ban page: `openspec/specs/core_plugin_appsec_bot-detection/spec.md`. It does not name CSP replace or multi-cookie as scenarios.
- Captcha empty-body relay (out of scope) already has a test: `pkg/bouncer/zzz_bouncer_test.go` `TestHandleNextServeHTTPEmptyCaptchaBodyRelaysStatus`.

## Desired
- Tests in this repo that assert the protocol for both upstream cases:
  - operator ban page, not HTTP 200 with an empty body, when challenge `user_body_content` is missing or empty
  - exactly one `Content-Security-Policy` equal to the AppSec value when a CSP was already on the writer
  - each `user_cookies` value remains its own `Set-Cookie`
- A passing test is the proof.
- Do not change production behavior unless a test shows the protocol behavior is absent.
- Delivery card (PR summary) must name https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397.

## Affected
- `pkg/bouncer/zzz_bouncer_test.go` (existing AppSec envelope tests; new assertions belong here unless explore finds a better neighbor).
- `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` / `handleAppsecResponseServeHTTP` only if a test shows the protocol is absent.

## Out of scope
- Changing the upstream repository (maxlerebourg/crowdsec-bouncer-traefik-plugin).
- The AppSec captcha empty-body path (that action is specified to relay status).
- New config keys.

## Unknowns
- Whether explore treats `TestHandleNextServeHTTPEmptyChallengeBodyBans` as enough for case 1, or requires ban-page body plus an explicit empty-string `user_body_content` case.
- Whether a pre-set CSP on `httptest.ResponseRecorder` is a fair stand-in for "already on the writer" (recorder starts empty).
- Whether a failing new test will force a production change (current code looks protocol-correct; that is unproven until the tests run).

## Tensions
- Existing empty-challenge test covers missing body as 403 + ban header, but the ticket asks for the operator ban page and the empty-string case, which that test does not assert (`banTemplate` is nil).
- Production already fail-closes before `WriteHeader` and replaces same-name `user_headers`; the ticket says not to change production unless a test shows absence.
- Live spec covers empty-challenge ban; CSP replace and separate `Set-Cookie` values are not named there.
