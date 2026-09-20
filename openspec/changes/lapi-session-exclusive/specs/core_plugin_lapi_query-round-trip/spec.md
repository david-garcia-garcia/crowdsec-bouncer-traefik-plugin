## ADDED Requirements

### Requirement: LAPI and CAPI requests use the Client IO context
`sendQuery` and live lookups SHALL build the HTTP request with `http.NewRequestWithContext` using the Client IO context (`core_plugin_lapi_connection`). A cancelled IO context SHALL fail the in-flight exchange instead of leaving the GET running. Token-renewal replay SHALL use the same Client IO context. `drainMetrics` and `reportMetrics` MUST NOT use that IO context; those POSTs SHALL use `context.Background()` so Sleep’s async drain and Close’s sync drain still reach LAPI. AppSec query construction is out of scope for this requirement.

#### Scenario: Cancelled IO context fails the in-flight GET
- **WHEN** `sendQuery` has started a LAPI GET on the Client IO context
- **AND** that context is cancelled
- **THEN** the call returns a context error
- **AND** the GET does not complete as a successful 2xx body

#### Scenario: Metrics drain still POSTs after Sleep
- **WHEN** Sleep cancels the Client IO context
- **AND** remaining usage-metrics are drained
- **THEN** that POST uses `context.Background()`
- **AND** the drain is not cancelled by Sleep
