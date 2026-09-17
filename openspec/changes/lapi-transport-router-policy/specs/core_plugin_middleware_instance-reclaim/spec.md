## MODIFIED Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, the session prefix and cache prefix SHALL be derived from mode, LAPI scheme/host/path and lapiKey (CAPI machine+password in alone). Intervals, Redis store knobs, and `decisionScopeHeaders` MUST NOT be in that prefix. Per-router policy (`crowdsecLapiFailureAction`, `crowdsecRedisCacheUnreachableBlock`, `defaultDecisionSeconds`, `streamStartupBlock`), HTTP timeout, and LAPI TLS extras MUST NOT be in the session prefix or the LAPI settings hash. AppSec host, key, TLS, and body limit MUST NOT be in the LAPI session prefix, LAPI settings hash, or live/none LAPI identity. The LAPI reclaim `Open` key SHALL be that prefix plus a hash of the remaining LAPI settings (intervals, Redis, scopes header map, etc.) so a sleeping incarnation does not occupy a new snapshot’s slot. Middleware name, `next`, templates, trusted IPs, and Enabled MUST NOT be in that key. Live/none SHALL keep a reclaim key from LAPI connection identity (no stream cursor, no AppSec fields). Client address SHALL come from `pkg/ip.GetRemoteIP`. When a second live `New` on the same session prefix differs only on transport fields (HTTP timeout, LAPI TLS) or per-router policy removed from the hash, the joiner SHALL bind the live LAPI slot and the shared `lapi.Client` SHALL adopt the joiner’s transport without a new reclaim key. When the joiner differs on a field still in the settings hash, `PeekLivePrefix` SHALL warn-and-wire to the live LAPI slot (first New wins those hash fields).

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

#### Scenario: Reload changes only LAPI failure action keeps cursor
- **WHEN** the last holder of a stream session is cancelled and grace elapses
- **AND** a `New` for the same session differs only on `crowdsecLapiFailureAction`
- **THEN** the same reclaimed `lapi.Client` pointer is returned after Wake or bind
- **AND** the next stream fetch uses `startup=false` (no extra full resync solely for that reload)

#### Scenario: Reload changes only TLS keeps cursor
- **WHEN** the last holder of a stream session is cancelled and grace elapses
- **AND** a `New` for the same session differs only on an LAPI TLS field or `httpTimeoutSeconds`
- **THEN** the same reclaimed `lapi.Client` pointer is returned
- **AND** the LAPI HTTP transport is replaced on that client without `startup=true`

### Requirement: Snapshot change while sleeping opens a new reclaim key
When no live constructor context remains for a stream session and the previous slot is sleeping, a `New` with a **different** settings snapshot (hash fields that remain in `streamSettings`) SHALL `Open` a new reclaim key (session prefix plus the new settings hash). The sleeper SHALL remain until grace `Close()`. A `New` with the **same** settings snapshot SHALL `Open` (Wake) without `startup=true`. Changes excluded from the hash (per-router policy, transport-only fields) SHALL NOT alone open a new reclaim key. Last holder SHALL `Sleep()` tickers before grace.

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

### Requirement: Bouncer does not own the stream
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, effective LAPI failure action, Redis unreachable fail-closed, and live decision TTL from config) and MUST NOT start a process-wide stream ticker. The bouncer SHALL hold a `*lapi.Client` (nil when `crowdsecMode` is `appsec`) and a `*appsec.Client` (nil when AppSec is off).

#### Scenario: Second middleware does not start a second ticker
- **WHEN** two live stream configs disagree on update interval and share a LAPI key
- **THEN** one LAPI connection uses the interval from the first `New`
- **AND** the second `New` does not start another ticker

#### Scenario: Appsec mode skips LAPI Open
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is true
- **THEN** `New` does not reclaim an `lapi.Client`
- **AND** `New` reclaims an `appsec.Client`
- **AND** the bouncer still uses the constructor ctx as the AppSec reclaim holder
