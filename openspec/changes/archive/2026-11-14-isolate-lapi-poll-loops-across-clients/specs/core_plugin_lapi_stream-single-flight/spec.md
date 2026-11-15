## MODIFIED Requirements

### Requirement: Stream poll is single-flight per DecisionStore session
`handleStreamTicker` SHALL skip when DecisionStore `streamPollInFlight` is set. The in-flight guard SHALL be an `int64` field published with `sync/atomic` (`CompareAndSwapInt64` to enter, `StoreInt64` to release). Release SHALL run on every path, including panic. The guard SHALL cover the stream poll timer, `startStream`'s asynchronous first poll, and `Wake`. A busy tick MUST be dropped, not queued. Sleep MUST NOT wait for the in-flight `Do`. Close SHALL stop the poll timers and `closeIdle` and MUST NOT cancel the in-flight GET. An in-flight poll MAY finish apply after Close starts. Implementations MUST NOT add a Client IO cancel context for this skip. The stream loop SHALL be a poll timer on `time.AfterFunc`: it MUST run `work()` on the timer goroutine (no extra `go` per fire) and SHALL re-arm for one interval after `work()` returns unless it was stopped. Sleep and Close SHALL stop it; a stopped timer MUST NOT run `work()` again after any fire already in progress. Non-test code in `pkg/lapi` MUST NOT contain a `select` statement: yaegi v0.16.1 `_select` shares one case slice per statement across every goroutine that runs it, including the loops of different Clients. Implementations MUST NOT range over `ticker.C` (`Ticker.Stop` does not close `C`). There is no stream lease (`updated` / `Acquire`); this intra-instance lock is the overlap guard. Distinct pods are distinct CrowdSec rows (LAPI URL+key and the IP LAPI sees). Implementations MUST NOT use `atomic.Pointer[T]`, `atomic.Bool`, or `atomic.Int64` as a struct field and MUST NOT hold `Client.mu` across the LAPI HTTP call.

#### Scenario: Slow poll longer than the interval
- **WHEN** the stream interval is 1s and LAPI takes longer than 1s
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
- **WHEN** many poll timers of the same kind run concurrently under yaegi v0.16.1
- **AND** half of them are stopped
- **THEN** every stopped timer runs `work()` no more
- **AND** every other timer keeps running its own `work()`

#### Scenario: No select statement in pkg/lapi
- **WHEN** the non-test Go files of `pkg/lapi` are parsed
- **THEN** none contains a `select` statement

#### Scenario: Sleep stops the stream ticker
- **WHEN** Sleep stops the stream poll timer
- **THEN** that timer runs `work()` no more after any fire already in progress
