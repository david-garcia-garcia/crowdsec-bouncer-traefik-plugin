# Stream single-flight

## Language

**Stream single-flight**:
The session-scoped skip-if-busy guard so one DecisionStore runs at most one stream GET+apply at a time. It owns the CrowdSec cursor and the applied cache, not this HTTP client.
_Avoid_: Client IO cancel context, queueing mutex, `atomic.Pointer[T]`, `atomic.Bool`, `atomic.Int64`, a `select` in `pkg/lapi`

**Poll timer**:
The `time.AfterFunc` loop (`pollTimer`) one Client runs for its stream poll and, separately, for its usage-metrics push. It calls `work()` on the stdlib timer goroutine and re-arms one interval after `work()` returns until `stop`. The stream timer (`startRetryPollTimer`) runs its first poll at once, and after a poll that failed or was skipped re-arms `failedPollRetry` later (60 s, or one interval if shorter).
_Avoid_: ticker loop, `select` loop, stop channel

## Overview

`handleStreamTicker` enters with `TryBeginStreamPoll` on the DecisionStore and releases with `defer EndStreamPoll`. A busy tick is dropped. The same guard covers every poll of the stream poll timer, including the first poll it runs at once from `startStream` and `Wake`. `streamReady` and `streamPollInFlight` live on the store; a reincarnated Client must not zero them. Client startup, healthy, and update-failure stay `int64` fields on Client so `StreamHealthy` and `streamQuery` can run on the request path. Specs: `core_plugin_lapi_stream-single-flight`. There is no stream lease; every tick that wins the CAS GETs stream. Do not cancel the in-flight `Do` (LAPI already advanced `stream_cursor`).

## How to use

- Put the in-flight CAS at the top of `handleStreamTicker`. Release on every path, including panic.
- Do not add a second `go` around the poll `work()`, and do not start the first stream poll beside the timer: `startRetryPollTimer` runs it at once on the `time.AfterFunc` goroutine, so its result sets the next wait. `handleStreamTicker` returns whether the poll succeeded.
- Publish `isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, and `updateFailure` with `atomic.LoadInt64` / `StoreInt64` (and `AddInt64` for the failure count). Mirror `streamFetches`.
- Do not hold `Client.mu` across `crowdsecQuery`. That mutex is lifecycle plus the live header-scope registry.
- Do not use `atomic.Pointer[T]`, `atomic.Bool`, or `atomic.Int64` as a struct field (Yaegi v0.16.1).
- Do not add a `select` anywhere in `pkg/lapi` non-test code (`Test_lapiHasNoSelectStatement`). Start and stop the stream loop with `startPollTimer` / `pollTimer.stop`. Yaegi `interp._select` can also lose a timer wake (`std_go_reclaim.md`).

## Pattern snippet

```go
if c.decisionStore == nil || !c.decisionStore.TryBeginStreamPoll() {
	return
}
defer c.decisionStore.EndStreamPoll()
```

## Key files

- `pkg/lapi/client_stream.go`
- `pkg/decisionstore/store.go`
- `pkg/lapi/client.go`
- `pkg/lapi/poll_timer.go`

## Gotchas

- Single-flight is the only skip. A dropped tick does not GET stream and does not apply. It logs `handleStreamTicker:skip` at WARN. Identity (`traefikName`, `instanceName`, `leg`, `sessionKey`) lives on the LAPI constructor `log.With` child (`std_go_logger_nested`).
- `Sleep` and `Close` only signal the ticker. They do not wait for an in-flight GET and MUST NOT cancel it. `Wake` must hit the same store CAS.
- Yaegi v0.16.1 `_select` shares one case slice per statement across every goroutine that runs it, including the loops of different Clients (one Client per LAPI middleware). That is why the loops are a `pollTimer` on `time.AfterFunc` and not a `select`. Do not `for range ticker.C` (`Ticker.Stop` does not close `C`). Sleep and Close call `pollTimer.stop` and nil the field; stop does not wait for a `work()` already running.
- The next poll starts one interval after the previous `work()` returned (fixed delay), not on a fixed-rate tick. After a failed or skipped stream poll it starts `failedPollRetry` later instead, so `alone` (7200 s) is not unhealthy for 2 hours after CAPI is back. With the 60 s stream default both waits are the same.
- Cancelling a stream GET after LAPI wrote the body loses those deltas (`ext_crowdsec_lapi_stream-cursor`).
