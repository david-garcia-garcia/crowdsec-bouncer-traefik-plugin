# Requirement
IssueKey: 2026-09-06-upstream-377-stream-poll-freeze

## Problem
Upstream #377 reports that in stream mode the plugin intermittently stops polling `GET /v1/decisions/stream` for ~20 minutes while `POST /v1/usage-metrics` keeps firing. During the gap, newly banned IPs are not propagated to the Traefik bouncer cache; Traefik keeps serving traffic.

## Current (code)
- `pkg/lapi/client_stream.go:66-131` — `handleStreamCache` uses cache lease key `updated`; on miss sets lease then calls `crowdsecQuery` for the stream route; logs `handleStreamCache:updated` on success.
- `pkg/lapi/client_stream.go:42-44` — `startStream` registers a stream ticker calling `handleStreamTicker` every `updateIntervalSeconds`.
- `pkg/lapi/client.go:294-307` — `startTicker` launches `go work()` on each tick without waiting for the prior poll to finish.
- `pkg/lapi/client.go:251-273` — `Wake()` restarts the stream ticker and also spawns `go c.handleStreamTicker()` while a ticker may already be running.
- `pkg/lapi/client_stream.go:48-63` — `updateFailure`, `isCrowdsecStreamHealthy`, and `isCrowdsecStreamStartup` are read/written with no mutex when overlapping polls run.
- `pkg/lapi/client_stream.go:67-72` — lease hit on `updated` returns `nil` (success) without knowing whether an in-flight poll will fail.
- `pkg/lapi/client.go:162-169` — `http.Client.Timeout` is set from `HTTPTimeoutSeconds` (default 10s).
- `pkg/lapi/client_http.go:78-113` — `crowdsecQuery` uses `httpClient.Do` with that timeout.
- `pkg/lapi/session_test.go`, `pkg/lapi/client_range_test.go` — reclaim and range stream tests exist; no test for sustained poll gaps or overlapping Wake/ticker polls.
- `openspec/changes/archive/2026-09-06-one-stream-per-lapi-session/specs/core_plugin_middleware_instance-reclaim/spec.md` — requires only one `handleStreamCache` loop per session.

## Desired
- Fix the stream poll stall so `GET /v1/decisions/stream` cannot silently stop for extended periods while metrics keeps running.
- Serialize stream polling per `Client` (one poller / single-flight) per the one-stream-per-lapi-session spec.
- Ensure failure accounting and stream health reflect actual LAPI fetch outcomes; a lease short-circuit must not mask an in-flight failure.
- Add tests that overlapping `Wake()`/ticker polls and timeout behavior cannot produce extended gaps without logged failures.

## Affected
- `pkg/lapi/client_stream.go`
- `pkg/lapi/client.go`
- `pkg/lapi/client_http.go` (if `crowdsecQuery` timeout path needs hardening)
- `pkg/lapi/*_test.go`

## Out of scope
- CrowdSec LAPI/SQLite-side issues ruled out by the reporter.
- Reclaim/OpenStream wiring (covered by `session_test.go`).
- Redis-backed multi-instance lease semantics per cache prefix.
- Changing metrics ticker behavior (works during the reported freeze).

## Unknowns
- Whether the ~20-minute duration maps to a specific Go/net/http stall beyond `HTTPTimeoutSeconds`, or solely to overlapping polls plus lease masking (reporter hypothesis unconfirmed).

## Tensions
- `startTicker` uses `go work()` to avoid blocking the ticker goroutine but permits overlapping `handleStreamCache` calls that violate the one-poller spec.
- Duplicate `handleStreamCache:updated` at resumption in the issue aligns with the `Wake()` + ticker overlap pattern.
- `HTTPTimeoutSeconds` should bound `crowdsecQuery`, but the reporter saw ~20 minutes of silence with no errors logged.
