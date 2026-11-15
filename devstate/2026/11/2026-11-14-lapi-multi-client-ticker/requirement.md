# Requirement
IssueKey: 2026-11-14-lapi-multi-client-ticker

## Problem
Under yaegi v0.16.1 every goroutine that executes the same `select` statement shares one case slice. Each `lapi.Client` runs its own stream loop (`runStreamTicker`) and metrics loop (`runMetricsTicker`), so two or more Clients (several LAPI middlewares, a reload that keeps the old Client in reclaim grace beside a new one, Sleep→Wake) run the same statement concurrently. A loop can then wait on, and receive, another Client's tick or stop. Reproduced: 2–12 crossed ticks in 200 000 per loop, 5 of 5 runs, two `RunStreamTickerForTest` loops under yaegi. A crossed stop can silently end one middleware's stream polling (inference, not reproduced).

## Current (code)
- `pkg/lapi/client.go` `runStreamTicker` / `runMetricsTicker`: one `select` on `ticks` and `stop` each; split from each other by 886d88bd (#171), shared across Clients.
- `pkg/lapi/client.go` `startStreamTicker` / `startMetricsTicker`: one `time.Ticker` and one buffered `stop` per call; `defer ticker.Stop()` when the loop returns.
- `pkg/lapi/client.go` `stopTicker`: non-blocking send on the buffered stop.
- `pkg/lapi/client.go` `Close` / `Sleep` / `Wake`: stop and nil `streamStop` / `metricsStop`, or start them again.
- `pkg/lapi/client_stream.go` `startStream`: starts the stream loop for stream and alone modes.
- `pkg/lapi/identity.go` `OwnershipKey`: includes the middleware name, so one Client per LAPI middleware.
- `pkg/lapi/zzz_ticker_own_channel_test.go`: yaegi and native tests that cover one stream loop beside one metrics loop only.
- `pkg/lapi/test_client.go` `RunStreamTickerForTest` / `RunMetricsTickerForTest`: exports for the yaegi program.

## Desired
- Each Client's stream loop and metrics loop receives only its own ticks and its own stop under yaegi v0.16.1, for any number of Clients running the same loop code.
- Stopping one Client (Sleep or Close) never stops or stalls another Client's loop, and the stopped loop ends.
- Sleep / Wake / Close keep their contract: signal only, never wait for or cancel an in-flight stream GET; Wake restarts the loops.
- Regression tests: under yaegi, several loops of the same kind on their own channels (fails on master); stopping one loop leaves another running.
- Delivery card names upstream PR 399 and issue 377.

## Affected
- `pkg/lapi/client.go`
- `pkg/lapi/client_stream.go`
- `pkg/lapi/test_client.go`
- `pkg/lapi/zzz_ticker_own_channel_test.go`
- `knowledge/devdocs/core_plugin_lapi_stream-single-flight.md`
- `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`
- `openspec/specs/` leaf for the stream single-flight / ticker contract (not located yet)

## Out of scope
- Other problems from the 2026-11-14 upstream review.
- Workflow files.
- LAPI poll semantics beyond what the loop fix needs.
- Copying upstream PR 399 (range over `ticker.C` without a stop never ends after `Ticker.Stop`).

## Unknowns
- Loop shape that is yaegi-safe and still stops: `time.AfterFunc` rescheduling (reclaim precedent), a per-execution `for range` on an owned channel, or another shape.
- Whether rescheduling after `work()` (fixed delay) instead of a fixed-rate ticker is acceptable for stream and metrics intervals.
- Whether any other `select` in a per-Client or per-instance goroutine shares the same exposure.
- A deterministic reproduction of the crossed stop.

## Tensions
- `core_plugin_lapi_stream-single-flight.md` says "Do not add a new `select` on a timer" and "Do not `for range ticker.C`" and keeps `stopTicker`; the fix may replace the buffered-stop contract.
- Review proposal (`time.AfterFunc`) vs the devdoc line "Do not extract a helper that contains the `select`" (written for the single-Client split).
