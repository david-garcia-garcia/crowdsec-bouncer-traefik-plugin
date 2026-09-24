## Why

This repo needs tests that prove AppSec challenge protocol against upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397: empty or missing challenge `user_body_content` must fail-closed to the operator ban page (not HTTP 200 with an empty body), AppSec `user_headers` of the same name must replace (including Content-Security-Policy), and each `user_cookies` value must stay its own `Set-Cookie`. A passing test is the proof.

## What Changes

- Add tests in `pkg/bouncer/zzz_bouncer_test.go` next to the existing AppSec envelope cases for both #397 edges:
  - missing and empty-string challenge `user_body_content` with a non-nil `banTemplate` (operator ban page, not HTTP 200 empty body)
  - pre-set `Content-Security-Policy` on the writer is replaced by the AppSec value (exactly one header)
  - two `user_cookies` values remain two `Set-Cookie` headers
- Do not change production. Explore reproduction on dest master already shows the protocol is present (`applyAppsecServeHTTP` fail-closes before `WriteHeader`; `handleAppsecResponseServeHTTP` assigns `user_headers` and `Header().Add` per cookie).
- Fold CSP-replace and separate `Set-Cookie` scenarios into the live spec `core_plugin_appsec_bot-detection`. Empty challenge ban is already specified there.
- Out of scope: the upstream repository, AppSec captcha empty-body (already specified and tested), new config keys, e2e cases for these two protocol edges.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_bot-detection`: name the live promise that AppSec `user_headers` of the same name replace (CSP included) and that each `user_cookies` value is its own `Set-Cookie`. Empty challenge `user_body_content` remains the existing operator-ban scenario.

## Impact

- `pkg/bouncer/zzz_bouncer_test.go` only (new assertions beside `TestHandleNextServeHTTPEmptyChallengeBodyBans` and `TestHandleNextServeHTTPRelaysStructuredAppsecChallenge`).
- `openspec/specs/core_plugin_appsec_bot-detection` (delta fold).
- `pkg/bouncer/bouncer.go` only if a new test shows the protocol is absent (explore says it is present).
- Delivery card / PR summary must name https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/397.
