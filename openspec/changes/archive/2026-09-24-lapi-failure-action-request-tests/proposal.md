## Why

A failed stream poll and a LAPI captcha fallback are already the bouncer's job, but the tests never drive a real failed stream GET, and they never serve a captcha challenge for a LAPI failure. The healthy flag is flipped by hand instead.

## What Changes

- Add a stream-mode request test: `GET /v1/decisions/stream` returns 500, the client becomes unhealthy without `SetStreamHealthyForTest`, then `ServeHTTP` honors `bouncerLapiFailureAction`. `passthrough` calls next. `ban` does not and returns the ban status.
- Add a live-mode request test: LAPI returns 500 and `bouncerLapiFailureAction` is `captcha`. The response is the captcha challenge page.

## Capabilities

### New Capabilities

### Modified Capabilities

## Impact

- Tests in `zzz_servehttp_request_path_test.go` (or the stream neighbor of `TestServeHTTP_LiveFailureAction`).
- No production code. `openspec/specs/core_plugin_lapi_failure-action/spec.md` already requires these outcomes.
