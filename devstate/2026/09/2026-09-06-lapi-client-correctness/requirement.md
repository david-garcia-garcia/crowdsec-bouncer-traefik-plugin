# Requirement
IssueKey: 2026-09-06-lapi-client-correctness

## Problem

`pkg/lapi` has six related defects on LAPI client paths: concurrent stream polls race health state and can mask failures; transport errors can panic via nil `*http.Response`; alone-mode 401 retry drops POST bodies; live header-scope query errors fail-open; stream health transitions and stream JSON→cache apply lack unit tests.

## Current (code)

- `pkg/lapi/client.go:294-307` — `startTicker` spawns `go work()` each tick without waiting for prior poll.
- `pkg/lapi/client.go:271-272` — `Wake()` spawns `go c.handleStreamTicker()` while ticker may already run.
- `pkg/lapi/client_stream.go:38-40` — `startStream` may call `handleStreamTicker` synchronously or via `go` before ticker starts.
- `pkg/lapi/client_stream.go:48-63` — `updateFailure`, `isCrowdsecStreamHealthy`, `isCrowdsecStreamStartup` read/written without sync.
- `pkg/lapi/client_stream.go:66-72` — lease hit on `updated` returns success without knowing in-flight poll outcome.
- `pkg/lapi/client_decisions.go:15-16` — `streamQuery()` reads health/startup flags while other goroutines mutate them.
- `pkg/lapi/client_http.go:88-90` — `crowdsecQuery` reads `res.StatusCode` when `err != nil` and `res` may be nil.
- `pkg/lapi/client_http.go:97-101` — alone-mode 401 retry calls `crowdsecQuery(stringURL, nil)` (GET, no body).
- `pkg/lapi/client_http.go:78-84` — nil `data` selects `http.MethodGet`.
- `pkg/lapi/client_metrics.go:203-215` — metrics POST uses `crowdsecQuery(..., data)`.
- `pkg/lapi/client_live.go:17-25` — `handleNoStreamCache` propagates IP lookup errors only; scope loop ignores scope errors.
- `pkg/lapi/client_decisions.go:133-136` — `mergeLiveScope` logs debug and returns prior `chosen` on scope query error.
- `pkg/bouncer/bouncer.go:201-207` — `applyLapiFailureAction` only when `LiveLookup` returns error (scope errors never surface).
- `pkg/lapi/client_range_test.go:54-64` — stream cache tested for lease hit only, not LAPI body apply or health.
- `pkg/lapi/failure_action_test.go` — covers IP LAPI 500 only; no header-scope failure path.
- `pkg/lapi/*_test.go` — no test for nil-response transport, 401 POST retry, overlapping polls, or health threshold.

## Desired

- Serialize stream polling per `Client` so health fields and stream GETs cannot overlap; lease short-circuit must not count as success while another poll is failing.
- Guard `crowdsecQuery` against nil `res` on transport error; return unreachable without panic.
- Preserve HTTP method and replay POST body on alone-mode 401 retry.
- Propagate header-scope LAPI errors from `mergeLiveScope`/`handleNoStreamCache` so bouncer can apply `lapiFailureAction`.
- Add httptest coverage: stream health threshold/recovery, stream JSON apply (IP/header/range/delete), nil-response transport, 401 POST retry, live-scope error path.

## Affected

- `pkg/lapi/client.go`
- `pkg/lapi/client_stream.go`
- `pkg/lapi/client_http.go`
- `pkg/lapi/client_live.go`
- `pkg/lapi/client_decisions.go`
- `pkg/lapi/client_metrics.go` (via `crowdsecQuery` fix)
- `pkg/lapi/*_test.go` (new/extended tests)

## Out of scope

- OpenLive reclaim wiring (`session_test.go` already covers).
- Duplicate metrics goroutine at `New`.
- `getToken` JSON special-character injection.
- Redis-backed multi-instance lease semantics.
- Bouncer-side `applyLapiFailureAction` behavior beyond surfacing scope errors to `LiveLookup`.
- Choosing strongest remediation when both IP and scope return data successfully.
- Non-2xx handling when `res` is valid; TLS/mTLS config errors during `New`.
- Stream-mode LAPI 401 retry (not retried today).
- E2E CrowdSec integration.

## Unknowns

- Default `updateMaxFailure` value at runtime (ticket cites default 0 → first failure marks unhealthy; confirm from `configuration` / `New`).
- Whether scope-error propagation should return error when IP already banned vs only when IP allowed (ticket says “at minimum” like IP unreachable).

## Tensions

- Stream health tests should run polls synchronously to avoid concurrency bug masking results, but fixing concurrency may change timing assumptions in new tests.
- Scope fail-open fix may change live-mode behavior for operators relying on IP-only pass when scope query fails (ticket explicitly wants fail-closed / failure-action).
- `pkg/bouncer/bouncer.go:201-207` is out of scope for code changes but required for scope-error propagation to matter at runtime.
