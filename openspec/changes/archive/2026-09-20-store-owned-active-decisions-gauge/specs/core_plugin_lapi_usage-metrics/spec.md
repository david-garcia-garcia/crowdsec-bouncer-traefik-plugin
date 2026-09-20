## MODIFIED Requirements

### Requirement: Active decisions are a stream/alone gauge
In stream and alone modes, `active_decisions` SHALL be a gauge (unit `ip`) of Ip and header-scope decision records this connection currently applies, labeled `origin` (lists-rewritten) and `ip_type` of the decision value. Range CIDRs SHALL be omitted from this gauge until Range exact-CIDR forget lands. Live, none, and AppSec-only modes SHALL omit `active_decisions`. The gauge MUST NOT expand a CIDR into host addresses. Counts SHALL come from a DecisionStore snapshot at POST, not from a reporter-held per-slot map.

#### Scenario: Stream IP ban is counted
- **WHEN** stream applies one Ip ban whose value is `1.2.3.4` and origin is `crowdsec`
- **THEN** `active_decisions` includes 1 with `origin=crowdsec` and `ip_type=ipv4`

#### Scenario: Range CIDR is omitted from the gauge
- **WHEN** stream applies one Range ban whose value is `10.0.0.0/8` and origin is `crowdsec`
- **THEN** the next `active_decisions` window does not include that CIDR

### Requirement: MetricsReporter owns the usage-metrics window
The dropped window, processed atomics, last successful push time, and the POST/restore path SHALL live on a `MetricsReporter` that `Client` holds. `Client` MUST NOT keep those window fields on itself. The reporter MUST NOT keep `activeDecisionSlots` or `activeDecisionsByOriginIPType`. `IncProcessed`, `IncDropped`, `reportMetrics`, and `drainMetrics` SHALL remain `Client` methods that forward to that reporter. Envelope identity (`utc_startup_timestamp`, plugin version, mode) SHALL be snapshotted onto the reporter at construct and MUST NOT be `time.Now()` at each push. Stream/alone `reportMetrics` SHALL snapshot DecisionStore active counts and MUST NOT restore those counts on a failed POST (they are a gauge, not a window counter).

#### Scenario: Window survives transport replace
- **WHEN** a Client has unsent dropped or processed counts and a later bind replaces LAPI HTTP+auth
- **THEN** the next usage-metrics POST still includes those counts
- **AND** the POST uses the replaced transport

#### Scenario: Startup timestamp stays on the reporter
- **WHEN** two usage-metrics POSTs occur from the same Client
- **THEN** both send the same `utc_startup_timestamp`
- **AND** that value is the construct snapshot, not `time.Now()` at push

### Requirement: Active-decision slots store intern id and family
In stream and alone modes, DecisionStore SHALL keep compact origin-id × family counts. The reporter MUST NOT keep a per-slot forget map. `reportMetrics` SHALL snapshot store counts and send lists-rewritten origin names via `OriginName` at POST. When intern overflowed, that origin id is `0` and `OriginName` is empty (no leftover origin string). Live, none, and AppSec-only modes SHALL omit `active_decisions` items. The intern table owner is DecisionStore; the reporter MUST NOT own a second intern table. Stream apply MUST NOT remember or forget Ip, header, or Range keys on the reporter.

#### Scenario: Stream IP ban still posts origin name
- **WHEN** stream applies one Ip ban whose value is `1.2.3.4` and origin is `crowdsec`
- **THEN** `active_decisions` includes 1 with `origin=crowdsec` and `ip_type=ipv4`

#### Scenario: Forget drops that slot
- **WHEN** stream later deletes that same Ip slot
- **THEN** the next `active_decisions` window omits that record

#### Scenario: Overflow posts empty origin name
- **WHEN** intern overflowed and stream applies an Ip ban
- **THEN** `active_decisions` origin for that slot is empty
