## Context

See proposal.md. `New` starts the stream poll in a goroutine. The client begins healthy. Default `lapiUpdateMaxFailure` is `0`, so the first failed poll marks it unhealthy. `ServeHTTP` then applies `bouncerLapiFailureAction` on a cache miss.

## Goals / Non-Goals

**Goals:**

- Prove `passthrough` and `ban` after a real stream HTTP 500, through `New` and `ServeHTTP`.
- Prove `captcha` serves the challenge page after a live LAPI HTTP 500, through `New` and `ServeHTTP`.

**Non-Goals:**

- Production changes.
- A stream-mode captcha twin. Both paths share `applyLapiFailureAction`.
- AppSec failure-action tests.

## Decisions

- Drive the stream case with `cfgStreamAt` against an httptest server that returns 500 for the stream route. Wait until `testRoute(...).LapiClient().StreamHealthy()` is false, then `ServeHTTP`. Do not call `SetStreamHealthyForTest`.
- Alternative rejected: call `handleStreamTicker` on a bare client. The live failure test already uses `New`.
- Drive the captcha case like `TestServeHTTP_LiveFailureAction`, with captcha fields from `cfgAppsecCaptchaAt` (provider, gate, template `CAPTCHA_CHALLENGE_PAGE`, `X-Remediation`). LAPI returns 500. Assert the header and the page marker.
- `cfgStreamAt` sets `bouncerStartupBlock`. That flag is "is the client published", not "is the stream healthy". Waiting on `StreamHealthy` is still required so `ServeHTTP` does not run before the goroutine finishes.

## Risks / Trade-offs

- [Poll goroutine is slow or never flips] → deadline in the test; fail if still healthy. Default max-failure `0` flips on the first error, so one 500 is enough.
