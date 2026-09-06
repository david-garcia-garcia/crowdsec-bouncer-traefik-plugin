# Failure backoff Tracker

## Language

**Tracker**:
A tumbling-window failure counter on one reclaimed CrowdSec backend (LAPI Client or AppSec Client). After a threshold of recorded failures in the window it is unhealthy for a backoff timeout, then auto-recovers. The next outbound call is the probe.
_Avoid_: leaky bucket, token bucket, `UpdateMaxFailure`, `StreamHealthy`, per-router Bouncer field, package global

## Overview

Copy the sister traefik-modsecurity algorithm in `pkg/health`. Do not import that module (Yaegi). Failure action enums stay the owner of ban/captcha/passthrough.

## How to use

- Construct with `health.NewFromSeconds` from the operator knobs on `lapi.New` and `appsec.New`.
- Keep the Tracker on the Client, not on Bouncer.
- Call `IsUnhealthy` before outbound HTTP. If true, return the existing failure-action result without `Do`.
- Call `RecordFailure` only for backend misbehavior (live LAPI query/parse errors; AppSec unreachable/500). Do not record live bans, stream polls, or unreadable AppSec bodies.
- Opt-out: threshold `-1` or timeout `0`. Window `0` never resets the count except on recover.

## Pattern snippet

```go
if c.failureTracker != nil && c.failureTracker.IsUnhealthy() {
	return resultForFailureAction(pol.FailureAction, "appsecQuery:backoff")
}
res, err := c.httpClient.Do(req)
if err != nil {
	c.failureTracker.RecordFailure()
	return resultForFailureAction(pol.FailureAction, "appsecQuery:unreachable")
}
```

## Key files

- `pkg/health/tracker.go`
- `pkg/lapi/client_live.go`
- `pkg/appsec/query.go`

## Gotchas

- Warn on trip, Info on recover, Debug on skipped call.
- Two routers that disagree on backoff knobs get two Client incarnations (same as `HTTPTimeoutSeconds`).
