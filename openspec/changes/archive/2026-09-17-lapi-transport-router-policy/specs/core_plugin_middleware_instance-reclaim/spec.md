## MODIFIED Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, the session prefix and cache prefix SHALL be derived from mode, LAPI scheme/host/path and lapiKey (CAPI machine+password in alone). Intervals, Redis host/auth/db, HTTP timeout, LAPI failure action, LAPI TLS extras, `StreamStartupBlock`, live-cache TTL, Redis fail-closed, and `decisionScopeHeaders` MUST NOT be in that prefix. AppSec host, key, TLS, and body limit MUST NOT be in the LAPI session prefix, LAPI settings hash, or live/none LAPI identity. The LAPI reclaim `Open` key SHALL be that prefix plus a hash of the remaining first-wins LAPI settings (intervals, Redis host/auth/db/enabled, `updateMaxFailure`, CAPI scenarios, `decisionScopeHeaders`). That hash MUST NOT include LAPI failure action, Redis fail-closed, live-cache TTL, `StreamStartupBlock`, HTTP timeout, or the three LAPI TLS fields. Middleware name, `next`, templates, trusted IPs, and Enabled MUST NOT be in that key. Live/none SHALL keep a reclaim key from LAPI connection identity that drops the same per-router and transport fields (no stream cursor, no AppSec fields). Client address SHALL come from `pkg/ip.GetRemoteIP`. A second live `New` on the same session prefix with a different remaining LAPI settings hash SHALL `PeekLivePrefix` and warn-and-wire to the live LAPI slot (first `New` wins those knobs; INFO `ignored`). A second live `New` that differs only on dropped fields SHALL reuse the same reclaim key and the same Client.

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

#### Scenario: TLS-only reload keeps the Client and adopts transport
- **WHEN** a live stream incarnation exists
- **AND** a later `New` for the same LAPI URL and key differs only on LAPI TLS or HTTP timeout
- **THEN** both constructors receive the same Client
- **AND** that Client uses the later `New` transport
- **AND** an INFO line marks the joiner as `adopted`

### Requirement: Bouncer does not own the stream
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. The bouncer SHALL hold a `*lapi.Client` (nil when `crowdsecMode` is `appsec`) and a `*appsec.Client` (nil when AppSec is off). Two bouncers on one Client MAY apply distinct LAPI failure actions and Redis fail-closed values. Two live routers on one Client that disagree on live-cache TTL last-write that TTL into the shared live cache.

#### Scenario: Second middleware does not start a second ticker
- **WHEN** two live stream configs disagree on update interval and share a LAPI key
- **THEN** one LAPI connection uses the interval from the first `New`
- **AND** the second `New` does not start another ticker

#### Scenario: Appsec mode skips LAPI Open
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is true
- **THEN** `New` does not reclaim an `lapi.Client`
- **AND** `New` reclaims an `appsec.Client`
- **AND** the bouncer still uses the constructor ctx as the AppSec reclaim holder

#### Scenario: Two bouncers apply distinct LAPI failure actions
- **WHEN** two live middlewares reclaim the same `lapi.Client` and set different `crowdsecLapiFailureAction` values
- **THEN** each bouncer applies its own action on a LAPI miss or live LAPI error
- **AND** they still share one Client

#### Scenario: Per-router live TTL last-writes the shared cache
- **WHEN** two live middlewares reclaim the same `lapi.Client` and set different `defaultDecisionSeconds`
- **THEN** each lookup uses the TTL that bouncer passed
- **AND** the shared live cache keeps the last written TTL for that key

## ADDED Requirements

### Requirement: Last New wins LAPI transport
After `OpenStream` or `OpenLive` binds a Client, that `New` SHALL replace the Client’s LAPI HTTP+auth transport with the constructor config (last `New` wins). Concurrent replaces SHALL last-write the stored transport and idle-close the value they replaced. Remaining write-once Client scalars MUST NOT become mutable.

#### Scenario: Concurrent transport replace last-writes
- **WHEN** two constructors call transport replace on the same Client
- **THEN** the Client’s subsequent LAPI HTTP uses one of those transports
- **AND** the replaced HTTP client’s idle connections are closed
