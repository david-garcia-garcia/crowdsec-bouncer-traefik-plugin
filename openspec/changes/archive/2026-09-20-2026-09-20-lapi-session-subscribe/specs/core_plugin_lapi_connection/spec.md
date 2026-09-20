## MODIFIED Requirements

### Requirement: Lifecycle INFO includes session key and reason
`logInfo` SHALL include the reclaim session key (`SessionKey` for stream/alone, `Key` for live/none) and a `reason` field. Existing lifecycle reasons SHALL stay `started|sleeping|waking|closed`. On first `create()`, the `started` INFO SHALL say this LAPI key owns the process-wide stream and usage-metrics window in this instance. New INFO lines SHALL name transport replace and a live joiner whose transport was adopted. Session-owned knob mismatch MUST NOT be logged as `ignored` INFO (WARN is owned by `core_plugin_lapi_reclaim-key`). `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` MUST stay DEBUG.

#### Scenario: Lifecycle line carries key and reason
- **WHEN** a Client starts
- **THEN** the INFO line includes the reclaim key and `reason=started`
- **AND** `reclaim_put` is absent at INFO

#### Scenario: First create names process-wide ownership
- **WHEN** a stream Client `create()` runs
- **THEN** the INFO line includes the reclaim key and `reason=started`
- **AND** the line says this LAPI key owns the process-wide stream and usage-metrics window
