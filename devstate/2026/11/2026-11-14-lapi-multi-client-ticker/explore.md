# Explore

## Concepts

Units this change would touch:

- `startStreamTicker` / `runStreamTicker` (`pkg/lapi/client.go`): one `time.Ticker`, one buffered `stop`, one goroutine whose `select` waits on both and runs `work()` inline. One per Client in stream/alone mode.
- `startMetricsTicker` / `runMetricsTicker` (`pkg/lapi/client.go`): same shape for usage-metrics. One per Client when `lapiMetricsUpdateIntervalSeconds > 0`.
- `stopTicker` (`pkg/lapi/client.go`): `select { case stop <- true: default: }`. A third `select` statement, shared by every Close/Sleep in the process.
- `Client.Close` / `Sleep` / `Wake` (`pkg/lapi/client.go`), `startStream` (`pkg/lapi/client_stream.go`): own `streamStop` / `metricsStop` (`chan bool`).
- `OwnershipKey` (`pkg/lapi/identity.go`): includes the middleware name. One Client per LAPI middleware; a knob change on reload opens a new Client while the old one waits reclaim grace.
- `RunStreamTickerForTest` / `RunMetricsTickerForTest` (`pkg/lapi/test_client.go`) and `pkg/lapi/zzz_ticker_own_channel_test.go`: cover one stream loop beside one metrics loop only.

```
Client A ─ go runStreamTicker ─┐
Client B ─ go runStreamTicker ─┼─► ONE _select node ─► ONE []reflect.SelectCase (yaegi v0.16.1)
Client C ─ go runStreamTicker ─┘        each run writes Chan from its own frame, then reflect.Select(cases)
                                        → A can wait on B's ticker.C / stop
Close A, Close B ─ stopTicker ─► ONE _select node (send) → A's stop can be sent on B's chan
```

Call sites (roots searched: `pkg/**/*.go`, non-test): `startStreamTicker` 2 (`client.go` Wake, `client_stream.go` startStream); `startMetricsTicker` 2 (`client.go` New, Wake); `stopTicker` 4 (`client.go` Close ×2, Sleep ×2); `runStreamTicker` / `runMetricsTicker` 1 each (their start helpers) plus the 2 test exports. `select` statements in `pkg/` non-test code: 3, all in `pkg/lapi/client.go` (stopTicker, runStreamTicker, runMetricsTicker). No other per-instance `select` loop exists in `pkg/`.

Reproduce: **reproduced** on master HEAD 3388bbca under yaegi v0.16.1 (`C:/Users/DavidGarcíaGarcía/go/bin/yaegi`). Throwaway yaegi program through `yaegitest.Run`: two goroutines in `lapi.RunStreamTickerForTest`, each on its own unbuffered tick channel, 200 000 sends each, `GOMAXPROCS(2)`. 5 of 5 runs FAIL: `a=199988 b=200012`, `a=199998 b=200002`, `a=200009 b=199991`, `a=199997 b=200003`, `a=200011 b=199989` (want 200000 each). A crossed stop was **not reproduced** (rate too low to drive); its effect is inferred from the same shared slice.

Prototype (throwaway, scratchpad, under the same yaegi binary): 16 loops on `time.AfterFunc` + `Timer.Reset` after `work()`, 1 ms interval, `GOMAXPROCS(2)`. After stopping the 8 even loops, every stopped count froze and every running loop kept advancing (≈200 more each in 300 ms). Exit 0.

Outside facts: in-tree `knowledge/research/ext_yaegi_interp_select-cases/` (`_select` shares one case slice per statement; `rangeChan` allocates per execution). Reclaim precedent: `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/table.go` `parkAsleep` uses `time.AfterFunc` instead of `select` on a timer for the same yaegi reason (`knowledge/devdocs/std_go_reclaim.md`). Upstream: PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/399, issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377. No new research folder.

Usage packets stale after apply: `knowledge/devdocs/core_plugin_lapi_stream-single-flight.md`, `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` (both prescribe two `select` bodies and `stopTicker`).

## Decisions

- Replace both ticker loops and `stopTicker` with one unexported poll timer on `time.AfterFunc`: `work()` runs on the stdlib timer goroutine, then the timer is `Reset(interval)` unless stopped; stop sets a flag under the timer's mutex and calls `Timer.Stop`. No `select` remains in `pkg/lapi`, so nothing is shared across goroutines by yaegi.
- One helper serves stream and metrics: the two-body split only existed to keep two `select` statements apart; without a `select` there is nothing to split.
- Client keeps one poll-timer pointer per loop (`streamTimer`, `metricsTimer`), started in `New`/`startStream`/`Wake`, stopped and nil'd in `Sleep`/`Close`. Sleep/Close still only signal: they never wait for or cancel an in-flight `work()`.
- Interval becomes "interval after the previous `work()` returned" instead of a fixed-rate ticker. The old ticker already dropped ticks while `work()` ran (buffer 1), so a long poll was followed by an immediate extra poll; the new shape spaces polls by the interval. Single-flight still guards overlap with `startStream`'s first poll and `Wake`.
- Keep the `ticker:started` / `ticker:stopped` DEBUG lines, emitted from start and stop.
- Regression tests: (1) yaegi program driving the production poll timer with many loops of the same kind, stopping half, asserting stopped loops freeze and the others keep running; (2) an AST guard that `pkg/lapi` non-test code has no `select` statement (fails on master: 3); (3) native Sleep/Wake/Close tests that a Client's loops end and restart. Master failure of the tick-crossing property is the reproduction above.
- Live contract: MODIFY `core_plugin_lapi_stream-single-flight` and `core_plugin_lapi_usage-metrics` (both mandate the `select` + `stopTicker` shape). Propose runs FindSpecHost.
- Rejected: copy upstream PR 399 (`for range ticker.C`, drop stop). `Ticker.Stop` does not close `C`, so the goroutine never ends after Sleep/Close; the live specs forbid it.
- Rejected: one `select` per Client via generated/duplicated bodies. The share is per statement, not per function; any number of Clients still runs the same statement.
- Rejected: `for range` over an owned per-loop channel fed by a timer goroutine. Works under yaegi (`rangeChan` allocates per run) but needs a feeder goroutine and close ordering; `AfterFunc` already has the stop semantics and a precedent here.

## Open questions

- Q: Which loop shape is yaegi-safe across Clients and still stops on Sleep/Close?
  Rank: bounded asked — 2 startStreamTicker + 2 startMetricsTicker + 4 stopTicker call sites in pkg/lapi, all migrated here (roots: pkg/**/*.go); Desired "Each Client's stream loop and metrics loop receives only its own ticks and its own stop"
  Decision: assumed — `time.AfterFunc` poll timer with Reset after work and a stopped flag; no select in pkg/lapi.
  By: explore
- Q: Is fixed delay after work (instead of a fixed-rate ticker) acceptable for stream and metrics intervals?
  Rank: bounded asked — same call sites as above; Desired "Sleep / Wake / Close keep their contract" (interval cadence is not named, the old ticker already coalesced late ticks)
  Decision: assumed — yes; a poll never starts closer than one interval after the previous one ended. Card states it under Operators.
  By: explore
- Q: Does any other per-instance goroutine in pkg/ share a select statement the same way?
  Rank: additive asked — survey only; Desired "for any number of Clients running the same loop code"
  Decision: resolved — no; the only non-test `select` statements in pkg/ are the 3 in pkg/lapi/client.go, all removed by this change.
  By: explore
- Q: How does a regression test fail on master when the crossed stop cannot be driven deterministically?
  Rank: additive asked — new tests only; Desired "a yaegi test with several loops of the same kind ... that fails on master"
  Decision: assumed — an AST guard (no `select` in pkg/lapi non-test code) fails on master; the yaegi multi-loop test proves the new loop's isolation and independent stop; the 200 000-tick reproduction is recorded here as the master failure of the old loop.
  By: explore
