## MODIFIED Requirements

### Requirement: Usage-metrics share the Client reclaim lifetime
`Client` SHALL hold one `MetricsReporter` on the same reclaim table entry as the stream cursor. `Sleep`, `Wake`, and `Close` SHALL start and stop the existing metrics ticker with a function body whose `select` is a distinct statement from the stream ticker `select`. The plugin MUST NOT share one `select` statement across stream and metrics goroutines. `stopTicker` SHALL remain the non-blocking stop signal. Implementations MUST NOT copy upstream PR 399’s `for range ticker.C` without a stop case (`Ticker.Stop` does not close `C`). The plugin MUST NOT open a second reclaim entry or a second metrics ticker for usage-metrics. `metricsInterval` SHALL stay a write-once Client scalar. `drainMetrics` SHALL no-op when that interval is `<= 0`. Sleep SHALL POST remaining counters asynchronously. Close SHALL POST them synchronously before idle HTTP is closed. A failed POST SHALL restore the window for the next drain or ticker.

#### Scenario: Sleep drains on the same Client
- **WHEN** the last constructor context ends and reclaim Sleeps
- **THEN** the existing metrics ticker stops
- **AND** remaining window counters POST asynchronously
- **AND** no second reclaim key is created for metrics

#### Scenario: Wake resumes the same ticker
- **WHEN** Open during grace Wakes the same Client and `metricsInterval` is greater than 0
- **THEN** the distinct metrics ticker body starts
- **AND** the reporter field is the same instance

#### Scenario: Metrics ticker stays on its own channel
- **WHEN** stream and metrics ticker loops run concurrently under yaegi v0.16.1
- **THEN** the metrics loop receives only its own ticks

#### Scenario: Close stops the metrics ticker
- **WHEN** Close signals the metrics stop channel
- **THEN** the metrics ticker goroutine returns
- **AND** remaining window counters POST synchronously before idle HTTP is closed
