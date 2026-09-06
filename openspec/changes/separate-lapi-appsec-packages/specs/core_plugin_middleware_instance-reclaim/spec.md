## MODIFIED Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, the session prefix and cache prefix SHALL be derived from mode, LAPI scheme/host/path and lapiKey (CAPI machine+password in alone). Intervals, Redis, HTTP timeout, LAPI failure action, LAPI TLS extras, and `decisionScopeHeaders` MUST NOT be in that prefix. AppSec host, key, TLS, and body limit MUST NOT be in the LAPI session prefix, LAPI settings hash, or live/none LAPI identity. The LAPI reclaim `Open` key SHALL be that prefix plus a hash of those LAPI settings so a sleeping incarnation does not occupy a new snapshot’s slot. Middleware name, `next`, templates, trusted IPs, and Enabled MUST NOT be in that key. Live/none SHALL keep a reclaim key from LAPI connection identity (no stream cursor, no AppSec fields). Client address SHALL come from `pkg/ip.GetRemoteIP`. A second live `New` on the same session prefix with a different LAPI settings hash SHALL `PeekLivePrefix` and warn-and-wire to the live LAPI slot.

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

### Requirement: Unreclaimed connection is closed after grace
When no live constructor context remains for a LAPI connection key and grace elapses with no replace, the connection SHALL stop its tickers and release idle LAPI HTTP connections (`Close`). An `lapi.Connection` SHALL wait 30 seconds via `OpenWithGrace(..., ReclaimGraceDuration, ...)`. An `appsec.Client` SHALL use the same 30s grace. Table `DefaultGrace` SHALL remain 10 seconds. Values opened with `Open` SHALL use the table grace.

#### Scenario: Connection grace is not the table default
- **WHEN** the process table is constructed with a 20 millisecond grace
- **AND** the last holder of an `lapi.Connection` is cancelled
- **THEN** the incarnation is still sleeping after 20 milliseconds
- **AND** it is disposed after 30 seconds

### Requirement: Bouncer does not own the stream
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass) and MUST NOT start a process-wide stream ticker. The bouncer SHALL hold a `*lapi.Connection` (nil when `crowdsecMode` is `appsec`) and a `*appsec.Client` (nil when AppSec is off).

#### Scenario: Second middleware does not start a second ticker
- **WHEN** two live stream configs disagree on update interval and share a LAPI key
- **THEN** one LAPI connection uses the interval from the first `New`
- **AND** the second `New` does not start another ticker

#### Scenario: Appsec mode skips LAPI Open
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is true
- **THEN** `New` does not reclaim an `lapi.Connection`
- **AND** `New` reclaims an `appsec.Client`
- **AND** the bouncer still uses the constructor ctx as the AppSec reclaim holder
