## Why

A visitor who hits an AppSec bot-detection challenge is counted as dropped once per AppSec answer, including the fingerprint script, the proof-of-work worker, and the submit POST. Dest today never relays the challenge JSON (a 403 becomes a ban), so both the page and the internal paths increment `blockedRequests`. CrowdSec's usage-metrics window should count the challenge page once.

## What Changes

- Parse an AppSec JSON body that carries a non-empty `action`.
- When `action` is `challenge`, write `http_status`, `user_headers`, `user_cookies`, and `user_body_content` to the client instead of the operator ban page.
- Increment `blockedRequests` for that relay only when the request path is **not** under `/crowdsec-internal/challenge/`.
- Leave bans, captcha pages from `pkg/captcha`, and the metrics POST shape unchanged.
- Add a regression test: a challenge envelope on `/protected` increments dropped by 1; the same envelope on `/crowdsec-internal/challenge/submit` does not.

## Capabilities

### New Capabilities

None. Dest has no `openspec/specs/` catalog; this change sets `skip_specs: true` rather than bootstrapping one.

### Modified Capabilities

None.

## Impact

- `bouncer.go` `appsecQuery`, `handleNextServeHTTP`, and a new write path for the challenge envelope
- `bouncer_test.go` (or a sibling `*_test.go`) regression
- Metrics POST body and labels: unchanged
