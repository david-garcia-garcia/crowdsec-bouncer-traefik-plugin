## ADDED Requirements

### Requirement: MetricsReporter owns the usage-metrics window
The dropped window, processed atomics, `active_decisions` gauge maps, last successful push time, and the POST/restore path SHALL live on a `MetricsReporter` that `Client` holds. `Client` MUST NOT keep those window fields on itself. `IncProcessed`, `IncDropped`, `rememberActiveDecision`, `forgetActiveDecision`, `reportMetrics`, and `drainMetrics` SHALL remain `Client` methods that forward to that reporter. Envelope identity (`utc_startup_timestamp`, plugin version, mode) SHALL be snapshotted onto the reporter at construct and MUST NOT be `time.Now()` at each push.

#### Scenario: Window survives transport replace
- **WHEN** a Client has unsent dropped or processed counts and a later bind replaces LAPI HTTP+auth
- **THEN** the next usage-metrics POST still includes those counts
- **AND** the POST uses the replaced transport

#### Scenario: Startup timestamp stays on the reporter
- **WHEN** two usage-metrics POSTs occur from the same Client
- **THEN** both send the same `utc_startup_timestamp`
- **AND** that value is the construct snapshot, not `time.Now()` at push

### Requirement: Usage-metrics POST uses the replaceable LAPI transport
The reporter SHALL POST `v1/usage-metrics` through the Client LAPI query that loads the current transport on every call. The reporter MUST NOT store `*http.Client`. New atomic fields MUST use `atomic.Value` with a Yaegi why-comment, not `atomic.Pointer[T]`. Write-once Client scalars, including `metricsInterval`, MUST NOT become mutable.

#### Scenario: POST after transport replace
- **WHEN** `AdoptTransport` stores a new transport and a usage-metrics POST runs
- **THEN** the request uses that transport’s HTTP client and auth header
- **AND** the reporter has no `*http.Client` field

### Requirement: Usage-metrics share the Client reclaim lifetime
`Client` SHALL hold one `MetricsReporter` on the same reclaim table entry as the stream cursor. `Sleep`, `Wake`, and `Close` SHALL start and stop the existing metrics ticker with the same `startTicker` helper. The plugin MUST NOT open a second reclaim entry or a second metrics ticker for usage-metrics. `metricsInterval` SHALL stay a write-once Client scalar. `drainMetrics` SHALL no-op when that interval is `<= 0`. Sleep SHALL POST remaining counters asynchronously. Close SHALL POST them synchronously before idle HTTP is closed. A failed POST SHALL restore the window for the next drain or ticker.

#### Scenario: Sleep drains on the same Client
- **WHEN** the last constructor context ends and reclaim Sleeps
- **THEN** the existing metrics ticker stops
- **AND** remaining window counters POST asynchronously
- **AND** no second reclaim key is created for metrics

#### Scenario: Wake resumes the same ticker
- **WHEN** Open during grace Wakes the same Client and `metricsInterval` is greater than 0
- **THEN** the same `startTicker` helper starts the metrics ticker
- **AND** the reporter field is the same instance
