# Stream single-flight

## Language

**Stream single-flight**:
The session-scoped skip-if-busy guard so one DecisionStore runs at most one stream GET+apply at a time. It owns the CrowdSec cursor and the applied cache, not this HTTP client.
_Avoid_: Client IO cancel context, queueing mutex, `atomic.Pointer[T]`, `atomic.Bool`, `atomic.Int64`, a second `select`+timer loop

## Overview

`handleStreamTicker` enters with `TryBeginStreamPoll` on the DecisionStore and releases with `defer EndStreamPoll`. A busy tick is dropped. The same guard covers the stream ticker, `startStream`'s async first poll, and `Wake`. `streamReady` and `streamPollInFlight` live on the store; a reincarnated Client must not zero them. Client startup, healthy, and update-failure stay `int64` fields on Client so `StreamHealthy` and `streamQuery` can run on the request path. Specs: `core_plugin_lapi_stream-single-flight`. There is no stream lease; every tick that wins the CAS GETs stream. Do not cancel the in-flight `Do` (LAPI already advanced `stream_cursor`).

## How to use

- Put the in-flight CAS at the top of `handleStreamTicker`. Release on every path, including panic.
- Do not add a second `go` around the ticker `work()`. `startTicker` runs `work()` on the ticker goroutine. `stop` stays buffered.
- Publish `isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, and `updateFailure` with `atomic.LoadInt64` / `StoreInt64` (and `AddInt64` for the failure count). Mirror `streamFetches`.
- Do not hold `Client.mu` across `crowdsecQuery`. That mutex is lifecycle plus the live header-scope registry.
- Do not use `atomic.Pointer[T]`, `atomic.Bool`, or `atomic.Int64` as a struct field (Yaegi v0.16.1).
- Do not add a new `select` on a timer. Yaegi `interp._select` can lose a timer wake (`std_go_reclaim.md`).

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

## Gotchas

- Single-flight is the only skip. A dropped tick does not GET stream and does not apply. It logs `handleStreamTicker:skip` at WARN. Identity (`traefikName`, `instanceName`, `leg`, `sessionKey`) lives on the LAPI constructor `log.With` child (`std_go_logger_nested`).
- `Sleep` and `Close` only signal the ticker. They do not wait for an in-flight GET and MUST NOT cancel it. `Wake` must hit the same store CAS.
- Cancelling a stream GET after LAPI wrote the body loses those deltas (`ext_crowdsec_lapi_stream-cursor`).
