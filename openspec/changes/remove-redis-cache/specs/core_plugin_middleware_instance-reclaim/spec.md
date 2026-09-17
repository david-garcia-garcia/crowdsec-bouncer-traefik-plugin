## MODIFIED Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, the session prefix and cache prefix SHALL be derived from mode, LAPI scheme/host/path and lapiKey (CAPI machine+password in alone). Intervals, HTTP timeout, LAPI failure action, LAPI TLS extras, and `decisionScopeHeaders` MUST NOT be in that prefix. AppSec host, key, TLS, and body limit MUST NOT be in the LAPI session prefix, LAPI settings hash, or live/none LAPI identity. The LAPI reclaim `Open` key SHALL be that prefix plus a hash of those LAPI settings so a sleeping incarnation does not occupy a new snapshot’s slot. Middleware name, `next`, templates, trusted IPs, and Enabled MUST NOT be in that key. Live/none SHALL keep a reclaim key from LAPI connection identity (no stream cursor, no AppSec fields). Client address SHALL come from `pkg/ip.GetRemoteIP`. A second live `New` on the same session prefix with a different LAPI settings hash SHALL `PeekLivePrefix` and warn-and-wire to the live LAPI slot.

#### Scenario: Same LAPI key two names share one stream
- **WHEN** two `New` calls use stream mode, the same LAPI URL and key, and different middleware names, each with a live constructor context
- **THEN** both bouncers use the same LAPI connection incarnation
- **AND** only one stream ticker is running for that session

#### Scenario: Same LAPI key different metrics interval shares one stream
- **WHEN** two live stream `New` calls use the same LAPI URL and key and differ only on `metricsUpdateIntervalSeconds` (or only `updateIntervalSeconds`)
- **THEN** both bouncers use the same LAPI connection
- **AND** only one `handleStreamCache` loop runs for that key
- **AND** a warning names both middleware names and the ignored knobs

#### Scenario: Different LAPI hosts are isolated
- **WHEN** two `New` calls use different LAPI hosts in one process
- **THEN** two LAPI connection incarnations exist
- **AND** a decision present only on the first LAPI remediates only the first bouncer

#### Scenario: Same LAPI different AppSec hosts share one stream
- **WHEN** two live stream `New` calls use the same LAPI URL and key and different AppSec hosts, with AppSec enabled
- **THEN** both bouncers use the same LAPI connection
- **AND** each bouncer uses its own AppSec client incarnation

### Requirement: Snapshot change while sleeping opens a new reclaim key
When no live constructor context remains for a stream session and the previous slot is sleeping, a `New` with a **different** settings snapshot SHALL `Open` a new reclaim key (session prefix plus the new settings hash). The sleeper SHALL remain until grace `Close()`. A `New` with the **same** snapshot SHALL `Open` (Wake) without `startup=true`. Last holder SHALL `Sleep()` tickers before grace.

#### Scenario: Reload within grace Wakes
- **WHEN** every bound constructor context for a stream session is cancelled
- **AND** a `New` with the same session and same settings snapshot runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`
