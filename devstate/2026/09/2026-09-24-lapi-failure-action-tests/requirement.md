# Requirement
IssueKey: 2026-09-24-lapi-failure-action-tests

## Problem
Request-path tests do not prove `bouncerLapiFailureAction` when a stream poll fails, and they never serve a captcha challenge for a LAPI failure.

## Current (code)
- `pkg/bouncer/bouncer.go` `ServeHTTP`: stream or alone, cache miss, `StreamHealthy` false → `applyLapiFailureAction`. Healthy miss calls next.
- `pkg/bouncer/bouncer.go` `applyLapiFailureAction`: `passthrough` calls next, `captcha` remediates as captcha, default bans.
- `pkg/lapi/client.go`: stream client starts healthy (`isCrowdsecStreamHealthy: 1`).
- `pkg/lapi/client_stream.go` `handleStreamTicker`: a failed poll marks the stream unhealthy when `updateFailure >= updateMaxFailure` (default `0` in `pkg/configuration/configuration.go`, so the first failure flips it) and the client was healthy.
- `pkg/configuration/configuration.go`: `bouncerLapiFailureAction` default `ban`. Values `passthrough` | `ban` | `captcha`.
- `zzz_servehttp_request_path_test.go` `TestServeHTTP_LiveFailureAction`: live LAPI HTTP 500 through `New` and `ServeHTTP`. `ban` is 403. `passthrough` is 200. Not stream.
- `pkg/bouncer/zzz_servehttp_gaps_test.go` `TestServeHTTP_StreamUnhealthyUsesFailureAction`: `ban` and `passthrough` on `ServeHTTP`, after `SetStreamHealthyForTest(false)`. No stream HTTP failure.
- `pkg/bouncer/zzz_bouncer_test.go` `TestApplyLapiFailureAction`: calls `applyLapiFailureAction` directly. `passthrough` and `ban` only.
- `zzz_constructor_test.go` `TestNew_AppsecCaptchaFailureActionServesChallenge`: AppSec HTTP 500 serves the captcha page. Not LAPI.
- `pkg/appsec/zzz_failure_action_test.go`: AppSec query honors `passthrough`, `ban`, and `captcha`. Not the hole.
- not found: a test whose stream endpoint fails and then `ServeHTTP` asserts `passthrough` versus `ban`.
- not found: a request-path test with `bouncerLapiFailureAction: captcha` that serves the challenge.

## Desired
- A stream-mode request, after `GET /v1/decisions/stream` has failed, honors `bouncerLapiFailureAction`. `passthrough` calls next and does not block. `ban` does not call next and returns the ban status. Setting the healthy flag in the test does not satisfy this.
- A LAPI failure with `bouncerLapiFailureAction: captcha` serves the captcha challenge on the request path.

## Affected
- `pkg/bouncer/bouncer.go`
- `pkg/lapi/client_stream.go`
- `pkg/bouncer/zzz_servehttp_gaps_test.go`
- `zzz_servehttp_request_path_test.go`
- `zzz_constructor_test.go`

## Out of scope
- Changing `bouncerLapiFailureAction`, `bouncerAppsecFailureAction`, or their defaults.
- New AppSec failure-action tests.
- Changing when `lapiUpdateMaxFailure` marks the stream unhealthy.

## Unknowns
- Whether the stream assertion must go through `New` and the ticker, or may call the poll once and then `ServeHTTP`.
- Which LAPI failure (live HTTP 500 or a failed stream poll) the captcha challenge test should use.

## Tensions
- None. The ticket asks for tests of the existing knob. It does not ask the default (`ban`) to let traffic through.
