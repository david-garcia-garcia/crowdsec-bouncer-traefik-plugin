## MODIFIED Requirements

### Requirement: Stream poll is single-flight per DecisionStore session
`handleStreamTicker` SHALL skip when DecisionStore `streamPollInFlight` is set. The in-flight guard SHALL be an `int64` field published with `sync/atomic` (`CompareAndSwapInt64` to enter, `StoreInt64` to release). Release SHALL run on every path, including panic. The guard SHALL cover the stream ticker, `startStream`'s asynchronous first poll when `StreamStartupBlock` is false, and `Wake`. A busy tick MUST be dropped, not queued. Sleep MUST NOT wait for the in-flight `Do`. Close SHALL stop tickers and `closeIdle` and MUST NOT cancel the in-flight GET. An in-flight poll MAY finish apply after Close starts. Implementations MUST NOT add a Client IO cancel context for this skip. The stream ticker loop SHALL be a function body whose `select` is a distinct statement from the metrics ticker `select` (yaegi v0.16.1 `_select` shares one case slice per statement). That loop MUST run `work()` on the ticker goroutine (no extra `go` per tick) and SHALL wait on that loop’s ticker channel and a buffered stop. Sleep and Close SHALL stop it through `stopTicker`. Two copies of this helper are not a third poll loop. Implementations MUST NOT drop the stop channel for `for range ticker.C` (`Ticker.Stop` does not close `C`). There is no stream lease (`updated` / `Acquire`); this intra-instance lock is the overlap guard. Distinct pods are distinct CrowdSec rows (LAPI URL+key and the IP LAPI sees). Implementations MUST NOT use `atomic.Pointer[T]`, `atomic.Bool`, or `atomic.Int64` as a struct field, MUST NOT hold `Client.mu` across the LAPI HTTP call, and MUST NOT add a new `select`-plus-timer loop.

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

#### Scenario: Stream ticker stays on its own channel
- **WHEN** stream and metrics ticker loops run concurrently under yaegi v0.16.1
- **THEN** the stream loop receives only its own ticks
- **AND** `work()` still runs on the stream ticker goroutine

#### Scenario: Sleep stops the stream ticker
- **WHEN** Sleep signals the stream stop channel
- **THEN** the stream ticker goroutine returns
