## 1. Tracker

- [x] 1.1 Add `pkg/health` Tracker copied from traefik-modsecurity: tumbling window, trip at threshold, auto-recover after timeout, lockless healthy fast path
- [x] 1.2 `failureThreshold < 0` never trips; backoff timeout `0` never skips; window `0` never resets the count except on recover
- [x] 1.3 Unit tests: trip, window reset, opt-out, timeout 0, auto-recover, concurrent `IsUnhealthy`

## 2. Config

- [x] 2.1 Add six knobs on `Config` with JSON names `lapiFailureBackoffTimeout`, `lapiFailureBackoffBucketWindow`, `lapiFailureBackoffBucketThreshold`, `appsecFailureBackoffTimeout`, `appsecFailureBackoffBucketWindow`, `appsecFailureBackoffBucketThreshold`
- [x] 2.2 Defaults 30 / 30 / 5; validate timeout and window `>= 0`, threshold `>= -1`
- [x] 2.3 README next to `HTTPTimeoutSeconds` / failure-action knobs

## 3. LAPI

- [x] 3.1 Construct a Tracker on `lapi.Client` from the LAPI knobs; add the three fields to live/none identity (not stream session prefix)
- [x] 3.2 `LiveLookup`: if unhealthy, return error without HTTP so Bouncer `applyLapiFailureAction` runs
- [x] 3.3 RecordFailure on live `queryLiveDecisions` / `crowdsecQuery` errors and live parse errors, including header-scope queries; do not record `handleNoStreamCache:banned`; do not record stream polls
- [x] 3.4 Tests: skip HTTP while unhealthy; record on unreachable live lookup; banned decision does not record; stream poll still uses `updateMaxFailure`

## 4. AppSec

- [x] 4.1 Construct a Tracker on `appsec.Client` from the AppSec knobs; add the three fields to AppSec identity
- [x] 4.2 `Query`: if unhealthy, return `resultForFailureAction` without `Do`
- [x] 4.3 RecordFailure on Do error, 502/503/504, HTTP 500; do not record unreadable body or structured envelopes
- [x] 4.4 Tests: skip HTTP while unhealthy; record on unreachable/500; unreadable body does not record; `crowdsecAppsecFailureAction` still per-router

## 5. Close

- [x] 5.1 `go test` for `pkg/health`, `pkg/lapi`, `pkg/appsec`, `pkg/configuration`, `pkg/bouncer`
- [x] 5.2 Warn on trip, Info on recover, Debug on skipped call
