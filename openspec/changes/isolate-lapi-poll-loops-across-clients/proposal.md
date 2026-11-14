## Why

Under yaegi v0.16.1 every goroutine that runs the same `select` statement shares one case slice. Fork #171 split the stream and metrics loops so the two loops of one `lapi.Client` no longer share a statement, but there is one Client per LAPI middleware (and two during a reload that changes a client knob, or across Sleep→Wake). Those Clients all run the same `runStreamTicker`, `runMetricsTicker`, and `stopTicker` statements, so a loop can receive another Client's tick or stop. Reproduced on master: 2–12 crossed ticks per 200 000, 5 of 5 runs. A crossed stop can silently end one middleware's stream polling while `StreamHealthy` stays true. Upstream fixed its single-Client variant in https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/399 (issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377) by ranging over `ticker.C`; that shape never ends after `Ticker.Stop`, so this fork does not copy it.

## What Changes

- Replace the stream and metrics ticker loops and `stopTicker` with one poll timer on `time.AfterFunc`: `work()` runs on the stdlib timer goroutine, then the timer re-arms for one interval unless stopped. Stop sets a flag and stops the timer. No `select` remains in `pkg/lapi`.
- Client keeps one poll timer per loop. `New`/`startStream`/`Wake` start them; `Sleep`/`Close` stop and clear them. Sleep/Close still never wait for or cancel an in-flight `work()`.
- The next poll starts one interval after the previous `work()` returned (fixed delay), instead of on a fixed-rate ticker that queued one late tick.
- Regression tests under yaegi (many loops of the same kind, stop half) and an AST guard that `pkg/lapi` non-test code has no `select`.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- core_plugin_lapi_stream-single-flight: the stream loop is an `AfterFunc` poll timer with no `select`; isolation and independent stop hold across any number of Clients.
- core_plugin_lapi_usage-metrics: the metrics loop uses the same poll timer; `stopTicker` and the distinct-`select` rule go away.

## Impact

- `pkg/lapi/client.go` (loop helpers, `Close`, `Sleep`, `Wake`, `New`)
- `pkg/lapi/client_stream.go` (`startStream`)
- `pkg/lapi/test_client.go` (test exports for the yaegi program)
- `pkg/lapi/zzz_ticker_own_channel_test.go` (replaced by poll-timer tests)
- Usage packets `knowledge/devdocs/core_plugin_lapi_stream-single-flight.md`, `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`
