## Purpose

Keeps one DecisionStore session from running two stream polls at once and publishes stream startup, health, and failure counts so the request path can read them without a data race.

## Requirements

### Requirement: Stream poll is single-flight per DecisionStore session
`handleStreamTicker` SHALL skip when DecisionStore `streamPollInFlight` is set. The in-flight guard SHALL be an `int64` field on the store published with `sync/atomic` (`CompareAndSwapInt64` to enter, `StoreInt64` to release). Release SHALL run on every path, including panic. The guard SHALL cover the stream ticker, `startStream`'s asynchronous first poll when `StreamStartupBlock` is false, and `Wake`'s immediate poll. A busy tick MUST be dropped, not queued. Sleep MUST NOT wait for the in-flight `Do`. Close SHALL stop tickers and `closeIdle` and MUST NOT cancel the in-flight GET. An in-flight poll MAY finish apply after Close starts. Implementations MUST NOT add a Client IO cancel context for this skip. `startTicker` MUST run `work()` on the ticker goroutine (no extra `go` per tick). There is no stream lease (`updated` / `Acquire`); this intra-instance lock is the overlap guard. Distinct pods are distinct CrowdSec rows (LAPI URL+key and the IP LAPI sees). Implementations MUST NOT use `atomic.Pointer[T]`, `atomic.Bool`, or `atomic.Int64` as a struct field, MUST NOT hold `Client.mu` across the LAPI HTTP call, and MUST NOT add a new `select`-plus-timer loop.

#### Scenario: Slow poll longer than the interval
- **WHEN** the stream interval is 1s, LAPI takes longer than 1s, and `StreamStartupBlock` is false
- **THEN** at most one `handleStreamTicker` body is in flight
- **AND** stream fetches do not climb one per tick

#### Scenario: Wake skips while the store poll is in flight
- **WHEN** `Wake` starts a poll while `streamPollInFlight` is set on the DecisionStore
- **THEN** the second enter is skipped
- **AND** at most one CrowdSec `GET /v1/decisions/stream` is in flight

#### Scenario: New Client does not zero store poll flags
- **WHEN** a DecisionStore already has `streamReady` and `streamPollInFlight` set
- **AND** a new Client is constructed against that store
- **THEN** those store fields stay non-zero
- **AND** the new Client’s first `handleStreamTicker` is skipped

### Requirement: A new Client reads store streamReady before the first GET
`lapi.New` SHALL load DecisionStore `streamReady` (`int64`, `atomic.LoadInt64`) before the first stream GET. When that value is non-zero, `isCrowdsecStreamStartup` SHALL start at 0 so the first poll does not send `startup=true`. When it is zero (new empty store, including a mode change that produced a new `SessionHex`), `isCrowdsecStreamStartup` SHALL start at 1. Skip-if-busy SHALL use store `streamPollInFlight`, not a Client field. Live/none MUST NOT use this flag. Implementations MUST NOT use `atomic.Bool` or `atomic.Int64` as a struct field.

#### Scenario: New Client on a warm store skips startup true
- **WHEN** a DecisionStore already has `streamReady` set from a finished stream poll
- **AND** a new Client is constructed against that store
- **THEN** the Client’s first stream GET uses `startup=false`

#### Scenario: Mode change empty store starts at startup true
- **WHEN** mode change produces a new `SessionHex` and an empty DecisionStore
- **AND** a new stream Client is constructed against that store
- **THEN** the first stream GET uses `startup=true`

### Requirement: Stream health flags are published atomically
`isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, and `updateFailure` SHALL be `int64` fields published with `atomic.LoadInt64` and `atomic.StoreInt64` (and `AddInt64` for the failure count). `StreamHealthy` SHALL load `isCrowdsecStreamHealthy`. `streamQuery` SHALL load the startup and healthy fields when it builds `startup=`. Request-path reads MAY run concurrently with a poll write. Implementations MUST NOT take `Client.mu` to publish these fields across the HTTP poll.

#### Scenario: Request path reads StreamHealthy during a poll
- **WHEN** `ServeHTTP` calls `StreamHealthy` while `handleStreamTicker` writes health
- **THEN** the read is a synchronized load
- **AND** the race detector is silent
