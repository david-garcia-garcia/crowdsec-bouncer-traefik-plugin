## ADDED Requirements

### Requirement: Sleep and Close cancel the Client IO context
`Client` SHALL hold a `context.WithCancel` IO context used by LAPI/CAPI request construction (`core_plugin_lapi_query-round-trip`). `Sleep` and `Close` SHALL cancel it. `Wake` SHALL mint a new `WithCancel` (a cancelled context MUST NOT be reused). `drainMetrics` and `reportMetrics` MUST NOT use that IO context (`context.Background()`). `closeIdle` SHALL remain; it does not stop in-flight response bodies. AppSec reclaim and AppSec query context are unchanged.

#### Scenario: Sleep cancels an in-flight stream GET
- **WHEN** a stream GET is in flight on the Client IO context
- **AND** reclaim Sleeps the Client
- **THEN** that IO context is cancelled
- **AND** tickers are stopped

#### Scenario: Wake mints a new IO context
- **WHEN** a Client has been Sleep’d
- **AND** Wake runs
- **THEN** later `sendQuery` uses a new uncancelled context
- **AND** the cancelled Sleep context is not reused

#### Scenario: Close cancels IO then drains metrics
- **WHEN** Close runs on a live Client
- **THEN** the IO context is cancelled
- **AND** remaining usage-metrics POST on `context.Background()` before idle HTTP is closed
