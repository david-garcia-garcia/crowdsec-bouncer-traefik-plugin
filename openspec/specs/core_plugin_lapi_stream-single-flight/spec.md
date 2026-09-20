## Purpose

Keeps one LAPI Client from running two stream polls at once and publishes stream startup, health, and failure counts so the request path can read them without a data race.

## Requirements

### Requirement: Stream poll is single-flight per Client
`handleStreamTicker` SHALL skip when a poll is already running on that Client. The in-flight guard SHALL be an `int64` field published with `sync/atomic` (`CompareAndSwapInt64` to enter, `StoreInt64` to release). Release SHALL run on every path, including panic. The guard SHALL cover the stream ticker, `startStream`'s asynchronous first poll when `StreamStartupBlock` is false, and `Wake`. A busy tick MUST be dropped, not queued. `startTicker` MUST run `work()` on the ticker goroutine (no extra `go` per tick). There is no stream lease (`updated` / `Acquire`); this intra-instance lock is the overlap guard. Distinct pods are distinct CrowdSec rows (LAPI URL+key and the IP LAPI sees). Implementations MUST NOT use `atomic.Pointer[T]`, `atomic.Bool`, or `atomic.Int64` as a struct field, MUST NOT hold `Client.mu` across the LAPI HTTP call, and MUST NOT add a new `select`-plus-timer loop.

#### Scenario: Slow poll longer than the interval
- **WHEN** the stream interval is 1s, LAPI takes longer than 1s, and `StreamStartupBlock` is false
- **THEN** at most one `handleStreamTicker` body is in flight
- **AND** stream fetches do not climb one per tick

#### Scenario: Overlapping ticker and Wake
- **WHEN** `Wake` starts a poll while another poll on the same Client is still running
- **THEN** the second enter is skipped
- **AND** at most one CrowdSec `GET /v1/decisions/stream` is in flight

#### Scenario: Overlap still one fetch
- **WHEN** two `handleStreamTicker` calls overlap on one Client
- **THEN** exactly one LAPI stream GET occurs
### Requirement: Stream health flags are published atomically
`isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, and `updateFailure` SHALL be `int64` fields published with `atomic.LoadInt64` and `atomic.StoreInt64` (and `AddInt64` for the failure count). `StreamHealthy` SHALL load `isCrowdsecStreamHealthy`. `streamQuery` SHALL load the startup and healthy fields when it builds `startup=`. Request-path reads MAY run concurrently with a poll write. Implementations MUST NOT take `Client.mu` to publish these fields across the HTTP poll.

#### Scenario: Request path reads StreamHealthy during a poll
- **WHEN** `ServeHTTP` calls `StreamHealthy` while `handleStreamTicker` writes health
- **THEN** the read is a synchronized load
- **AND** the race detector is silent
