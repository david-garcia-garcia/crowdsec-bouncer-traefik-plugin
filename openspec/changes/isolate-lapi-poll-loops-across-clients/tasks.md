## 1. Regression tests

- [x] 1.1 Add an AST test that fails on master if any non-test file in `pkg/lapi` contains a `select` statement
- [x] 1.2 Add a yaegi test that starts many production poll timers of the same kind, stops half, and fails if a stopped loop keeps running or a running loop stalls
- [x] 1.3 Add native tests that a stopped poll timer ends, stop is idempotent and nil-safe, and two timers stop independently
- [x] 1.4 Replace `pkg/lapi/zzz_ticker_own_channel_test.go` (it drives the removed `select` loops)

## 2. Poll loop

- [x] 2.1 Add the `AfterFunc` poll timer in `pkg/lapi/client.go` (start, fire, stop) with `ticker:started` / `ticker:stopped` DEBUG lines
- [x] 2.2 Move `New`, `startStream`, `Wake`, `Sleep`, `Close` onto it; remove `startStreamTicker`, `startMetricsTicker`, `runStreamTicker`, `runMetricsTicker`, `stopTicker`
- [x] 2.3 Replace the `Run*TickerForTest` exports with a poll-timer export for the yaegi program

## 3. Usage docs

- [x] 3.1 Update `knowledge/devdocs/core_plugin_lapi_stream-single-flight.md` (poll timer, no `select`, across Clients)
- [x] 3.2 Update `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` (same timer for metrics)

## 4. Verify

- [x] 4.1 Run `go test ./pkg/lapi/...` with yaegi on PATH on this machine
- [x] 4.2 Run the full `go test ./...` and lint on this machine
