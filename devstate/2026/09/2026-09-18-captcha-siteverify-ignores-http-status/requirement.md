# Requirement
IssueKey: 2026-09-18-captcha-siteverify-ignores-http-status

## Problem
`Validate` treats a siteverify HTTP error as a successful solve when the body is JSON `{"success":true}`. HTTP 500 + `Content-Type: application/json` mints `crowdsec_captcha_gate` and 302s.

## Current (code)
- After `PostForm`, transport errors return `(false, err)`. Path: `pkg/captcha/captcha.go`.
- A received response is accepted when `Content-Type` starts with `application/json` and the decoded `success` field is true. `res.StatusCode` is never read. Path: `pkg/captcha/captcha.go`.
- `ServeHTTP` on `valid == true` mints the gate cookie and 302s. Path: `pkg/captcha/captcha.go`.
- Happy-path tests stub siteverify as 200 + `{"success":true}` (httptest default). Path: `pkg/captcha/zzz_servehttp_test.go`.
- `TestHunt_siteverifyHTTPErrorDoesNotAcceptSuccessJSON` is not on dest. Path: not found.
- Gate cookie after successful verify: `openspec/specs/core_plugin_middleware_captcha-gate/spec.md`.
- Siteverify HTTP status is not specified. Path: not found.

## Desired
Require a 2xx siteverify status before decoding `success`. Any other status is a failed verify: do not set `crowdsec_captcha_gate` and do not 302 as solved. Include a regression test. Bound to this defect only.

## Affected
- `pkg/captcha/captcha.go` (`Validate`; `ServeHTTP` only as the mint/302 caller)
- Captcha unit tests under `pkg/captcha/`

## Out of scope
- PR #28 transport errors (`PostForm` `err != nil`)
- Captcha request routing, custom-resource paths, form readers
- Gate cookie format, bind-IP, HMAC
- Empty-template panic and other hunt findings
- E2E mock / dummy siteverify always-success
- LAPI, AppSec, cache, configuration validation

## Unknowns
- Hunt test lives only in `wt-hunt-captcha` (`pkg/captcha/zzz_hunt_captcha_test.go`); dest has no copy. Implement must add a regression test in this tree.
- Non-2xx as `(false, nil)` (re-render challenge) vs `(false, err)` (HTTP 400). Ticket and hunt test only forbid cookie + solved 302.

## Tensions
- Ticket cites `TestHunt_siteverifyHTTPErrorDoesNotAcceptSuccessJSON` as proven FAIL; that name is not on `origin/master`.
- PR #28 made provider *transport* errors re-render 200 instead of bare 400. This ticket is HTTP status on a received body, not that path.
- Spec `core_plugin_middleware_captcha-gate` says "successful provider verify" then cookie+302; it does not define success when status is non-2xx.
