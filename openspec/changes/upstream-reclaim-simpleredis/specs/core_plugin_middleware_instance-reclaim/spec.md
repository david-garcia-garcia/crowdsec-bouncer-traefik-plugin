## MODIFIED Requirements

### Requirement: Unreclaimed connection is closed after grace
When no live constructor context remains for a LAPI connection key and grace elapses with no replace, the connection SHALL stop its tickers and release idle LAPI HTTP connections (`Close`). An `lapi.Client` SHALL wait 30 seconds (process table grace `ReclaimGraceDuration`). An `appsec.Client` SHALL use the same table. Open SHALL pass `reclaim.Hooks` for Sleep/Wake/Close.

#### Scenario: Connection grace is the process table wait
- **WHEN** the process table grace is 30 seconds
- **AND** the last holder of an `lapi.Client` is cancelled
- **THEN** the incarnation is still sleeping after 20 milliseconds
- **AND** it is disposed after 30 seconds
