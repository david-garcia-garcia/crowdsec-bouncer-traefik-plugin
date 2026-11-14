## MODIFIED Requirements

### Requirement: Usage-metrics share the Client reclaim lifetime
`Client` SHALL hold one `MetricsReporter` on the same reclaim table entry as the stream cursor. `Sleep`, `Wake`, and `Close` SHALL start and stop the existing metrics loop as an `AfterFunc` poll timer, the same helper as the stream loop (`core_plugin_lapi_stream-single-flight`). The metrics loop MUST NOT use a `select` statement. Implementations MUST NOT copy upstream PR 399’s `for range ticker.C` (`Ticker.Stop` does not close `C`). The plugin MUST NOT open a second reclaim entry or a second metrics loop for usage-metrics. `metricsInterval` SHALL stay a write-once Client scalar. `drainMetrics` SHALL no-op when that interval is `<= 0`. Sleep SHALL POST remaining counters asynchronously. Close SHALL POST them synchronously before idle HTTP is closed. A failed POST SHALL restore the window for the next drain or poll.

#### Scenario: Sleep drains on the same Client
- **WHEN** the last constructor context ends and reclaim Sleeps
- **THEN** the existing metrics poll timer stops
- **AND** remaining window counters POST asynchronously
- **AND** no second reclaim key is created for metrics

#### Scenario: Wake resumes the same ticker
- **WHEN** Open during grace Wakes the same Client and `metricsInterval` is greater than 0
- **THEN** a metrics poll timer starts
- **AND** the reporter field is the same instance

#### Scenario: Metrics ticker stays on its own channel
- **WHEN** several Clients run metrics poll timers concurrently under yaegi v0.16.1
- **AND** one Client stops its metrics timer
- **THEN** the other Clients' metrics timers keep running

#### Scenario: Close stops the metrics ticker
- **WHEN** Close stops the metrics poll timer
- **THEN** that timer runs `work()` no more after any fire already in progress
- **AND** remaining window counters POST synchronously before idle HTTP is closed
