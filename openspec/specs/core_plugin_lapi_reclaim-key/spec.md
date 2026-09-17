## Purpose

How this plugin keys a reclaimed `lapi.Client`: stream/alone `SessionKey` is session prefix plus first-wins settings hash; live/none `Key` is LAPI connection identity. A live joiner with a different remaining hash is warn-and-wire; a sleep snapshot change Opens a new key; an unreclaimed Client waits process-table `ProcessGrace` 30s.

## Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, the session prefix and cache prefix SHALL be derived from mode, LAPI scheme/host/path and lapiKey (CAPI machine+password in alone). Intervals, Redis host/auth/db, HTTP timeout, LAPI failure action, LAPI TLS extras, `StreamStartupBlock`, live-cache TTL, Redis fail-closed, and `decisionScopeHeaders` MUST NOT be in that prefix. AppSec host, key, TLS, and body limit MUST NOT be in the LAPI session prefix, LAPI settings hash, or live/none LAPI identity. The LAPI reclaim `Open` key SHALL be that prefix plus a hash of the remaining first-wins LAPI settings (intervals, Redis host/auth/db/enabled, `updateMaxFailure`, CAPI scenarios, `decisionScopeHeaders`). That hash MUST NOT include LAPI failure action, Redis fail-closed, live-cache TTL, `StreamStartupBlock`, HTTP timeout, or the three LAPI TLS fields. Middleware name, `next`, templates, trusted IPs, and Enabled MUST NOT be in that key. Live/none SHALL keep a reclaim key from LAPI connection identity that drops the same per-router and transport fields (no stream cursor, no AppSec fields). Visitor address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP` (do not parse `RemoteAddr`). A second live `New` on the same session prefix with a different remaining LAPI settings hash SHALL `PeekLivePrefix` and warn-and-wire to the live LAPI slot (first `New` wins those knobs; INFO `ignored`). A second live `New` that differs only on dropped fields SHALL reuse the same reclaim key and the same Client.

#### Scenario: Same LAPI key two names share one stream
- **WHEN** two `New` calls use stream mode, the same LAPI URL and key, and different middleware names, each with a live constructor context
- **THEN** both bouncers use the same LAPI connection incarnation
- **AND** only one stream ticker is running for that session

#### Scenario: Same LAPI key different metrics interval shares one stream
- **WHEN** two live stream `New` calls use the same LAPI URL and key and differ only on `metricsUpdateIntervalSeconds` (or only `updateIntervalSeconds`)
- **THEN** both bouncers use the same LAPI connection
- **AND** only one `handleStreamCache` loop runs for that key
- **AND** a warning names both middleware names and the ignored knobs
- **AND** an INFO line marks the joiner as `ignored`

#### Scenario: Different LAPI hosts are isolated
- **WHEN** two `New` calls use different LAPI hosts in one process
- **THEN** two LAPI connection incarnations exist
- **AND** a decision present only on the first LAPI remediates only the first bouncer

#### Scenario: Same LAPI different AppSec hosts share one stream
- **WHEN** two live stream `New` calls use the same LAPI URL and key and different AppSec hosts, with AppSec enabled
- **THEN** both bouncers use the same LAPI connection
- **AND** each bouncer uses its own AppSec client incarnation

#### Scenario: Failure-action-only reload keeps the Client
- **WHEN** a live stream incarnation exists
- **AND** a later `New` for the same LAPI URL and key differs only on `crowdsecLapiFailureAction`
- **THEN** both constructors receive the same Client
- **AND** no extra CrowdSec `startup=true` stream fetch runs for that reload

#### Scenario: TLS-only reload keeps the Client
- **WHEN** a live stream incarnation exists
- **AND** a later `New` for the same LAPI URL and key differs only on LAPI TLS or HTTP timeout
- **THEN** both constructors receive the same Client

### Requirement: Snapshot change while sleeping opens a new reclaim key
When no live constructor context remains for a stream session and the previous slot is sleeping, a `New` with a **different** settings snapshot SHALL `Open` a new reclaim key (session prefix plus the new settings hash). The sleeper SHALL remain until grace `Close()`. A `New` with the **same** snapshot SHALL `Open` (Wake) without `startup=true`. Last holder SHALL `Sleep()` tickers before grace.

#### Scenario: Reload within grace Wakes
- **WHEN** every bound constructor context for a stream session is cancelled
- **AND** a `New` with the same session and same settings snapshot runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`

#### Scenario: Redis host change does not overlap pollers
- **WHEN** the last holder of a stream session is cancelled
- **AND** a `New` for that session with a different `redisCacheHost` runs before grace ends
- **THEN** the previous ticker was already Sleep’d
- **AND** two `handleStreamCache` loops MUST NOT run on that session at once

### Requirement: Unreclaimed LAPI Client is closed after grace
When no live constructor context remains for a LAPI connection key and grace elapses with no replace, the connection SHALL stop its tickers and release idle LAPI HTTP connections (`Close`). An `lapi.Client` SHALL wait 30 seconds (process table grace `ProcessGrace`). Open SHALL pass `reclaim.Hooks` for Sleep/Wake/Close.

#### Scenario: Connection grace is the process table wait
- **WHEN** the process table grace is 30 seconds
- **AND** the last holder of an `lapi.Client` is cancelled
- **THEN** the incarnation is still sleeping after 20 milliseconds
- **AND** it is disposed after 30 seconds
