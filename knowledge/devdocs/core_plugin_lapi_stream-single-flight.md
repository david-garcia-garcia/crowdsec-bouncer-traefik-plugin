# Stream single-flight

## Language

**Stream single-flight**:
The intra-instance skip-if-busy guard so one Client runs at most one `handleStreamTicker` at a time.
_Avoid_: queueing mutex, `atomic.Pointer[T]`, `atomic.Bool`, `atomic.Int64`, a second `select`+timer loop

## Overview

`handleStreamTicker` enters with `CompareAndSwapInt64` on `streamPollInFlight` and releases with `defer StoreInt64`. A busy tick is dropped. The same guard covers the stream ticker, `startStream`'s async first poll, and `Wake`. Startup, healthy, and update-failure are `int64` fields published with `LoadInt64` / `StoreInt64` so `StreamHealthy` and `streamQuery` can run on the request path. Specs: `core_plugin_lapi_stream-single-flight`. The `updated` lease is a different job (`core_plugin_lapi_stream-lease.md`).

## How to use

- Put the in-flight CAS at the top of `handleStreamTicker`. Release on every path, including panic.
- Do not add a second `go` around the ticker `work()`. `startTicker` runs `work()` on the ticker goroutine. `stop` stays buffered.
- Publish `isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, and `updateFailure` with `atomic.LoadInt64` / `StoreInt64` (and `AddInt64` for the failure count). Mirror `streamFetches`.
- Do not hold `Client.mu` across `crowdsecQuery`. That mutex is lifecycle plus the live header-scope registry.
- Do not use `atomic.Pointer[T]`, `atomic.Bool`, or `atomic.Int64` as a struct field (Yaegi v0.16.1).
- Do not add a new `select` on a timer. Yaegi `interp._select` can lose a timer wake (`std_go_reclaim.md`).

## Pattern snippet

```go
if !atomic.CompareAndSwapInt64(&c.streamPollInFlight, 0, 1) {
	return
}
defer atomic.StoreInt64(&c.streamPollInFlight, 0)
```

## Key files

- `pkg/lapi/client_stream.go`
- `pkg/lapi/client.go`
- `pkg/lapi/client_decisions.go`

## Gotchas

- The `updated` lease does not serialize intra-instance flag writes. A lease loser still used to write startup; single-flight skips that enter.
- `Sleep` and `Close` only signal the ticker. They do not wait for an in-flight GET. `Wake` must hit the same CAS.
