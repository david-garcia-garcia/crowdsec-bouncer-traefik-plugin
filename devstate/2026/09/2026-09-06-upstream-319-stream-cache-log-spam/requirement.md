# Requirement
IssueKey: 2026-09-06-upstream-319-stream-cache-log-spam

## Problem
Upstream v1.6.0-alpha logged `handleStreamCache:updated` at INFO on every stream poll tick (default 60s), flooding Traefik logs. Upstream closed with PR #324 reverting to DEBUG. This fork needs tests proving the same INFO spam does not occur at default log level on `master`.

## Current (code)
- `pkg/lapi/client_stream.go:69` — lease hit path logs `handleStreamCache:alreadyUpdated` via `c.log.Debug`.
- `pkg/lapi/client_stream.go:129` — successful fetch path logs `handleStreamCache:updated` via `c.log.Debug`.
- `pkg/lapi/client_stream.go:42` — stream ticker uses `config.UpdateIntervalSeconds` (poll interval).
- `pkg/lapi/client_stream.go:53,59` — operator-visible stream health transitions use `logInfo` (INFO), not the cache tick messages.
- `pkg/lapi/client.go:276-281` — `logInfo` writes at slog INFO with mode and host attributes.
- `pkg/logger/logger.go:37-39` — unrecognized or empty `logLevel` defaults to INFO.
- `pkg/configuration/configuration.go:161` — default `LogLevel` is `LogINFO`.
- `pkg/configuration/configuration.go:178` — default `UpdateIntervalSeconds` is 60.
- `pkg/lapi/client_range_test.go:54-64` — `TestHandleStreamCacheLeaseHitHydrates` exercises lease-hit `handleStreamCache` but uses ERROR log level; no assertion on log level for cache tick messages.

## Desired
- Tests that prove `handleStreamCache:updated` and `handleStreamCache:alreadyUpdated` are emitted at DEBUG (not INFO), so default INFO log level does not spam Traefik on every poll tick.

## Affected
- `pkg/lapi/client_stream.go` (log call sites under test)
- `pkg/lapi/` test files (new or extended log-level assertions; `client_range_test.go` is the existing stream-cache test seam)

## Out of scope
- Changing product log levels unless a test cannot be honest without a one-line correctness fix.
- Verifying upstream PR #324 or v1.6.0-alpha behavior in this tree.
- Operator-visible stream health INFO lines (`MsgStreamHealthy` / `MsgStreamUnhealthy`).
- Behavior when operators explicitly set `logLevel=DEBUG` (periodic debug lines are expected).

## Unknowns
- Preferred test technique: slog record capture vs. static inspection of `log.Debug` call sites.
- Whether a lease-miss path test (full LAPI fetch) is needed in addition to lease-hit coverage.

## Tensions
- Ticket reports INFO spam at default log level; on `master` both cache tick messages use `Debug`, so the reported symptom should not reproduce at default INFO unless log level is DEBUG.
- Assessment status `present-fixed-unproven` with `proof: none` — behavior appears correct but lacks regression tests.
- Upstream issue closed as fixed; this run adds proof only, not a product behavior change.
