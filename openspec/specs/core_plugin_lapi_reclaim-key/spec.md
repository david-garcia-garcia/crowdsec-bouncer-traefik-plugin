## Purpose

How this plugin keys a reclaimed `lapi.Client`: stream/alone `SessionKey` is session prefix plus first-wins settings hash; live/none `Key` is LAPI connection identity. A live joiner with a different remaining hash is warn-and-wire; a sleep snapshot change Opens a new key; an unreclaimed Client waits process-table `ProcessGrace` 30s.

## Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, the session prefix SHALL be derived from mode, LAPI scheme/host/path and lapiKey (CAPI machine+password in alone). Intervals, Redis host/auth/db/read hosts, HTTP timeout, LAPI failure action, LAPI TLS extras, `StreamStartupBlock`, live-cache TTL, Redis fail-closed, and `decisionScopeHeaders` MUST NOT be in that prefix. AppSec host, key, TLS, and body limit MUST NOT be in the LAPI session prefix, LAPI Redis hash, or live/none LAPI identity. The LAPI reclaim `Open` key SHALL be `lapi:stream:` plus `SessionHex` plus a hash of Redis store parameters (`RedisCacheEnabled`, host, read hosts, password, database) — the same payload family as `StoreKey`, not a first-wins settings hash of intervals, `updateMaxFailure`, CAPI scenarios, or `decisionScopeHeaders`. That hash MUST NOT include LAPI failure action, Redis fail-closed, live-cache TTL, `StreamStartupBlock`, HTTP timeout, intervals, CAPI scenarios, `updateMaxFailure`, `decisionScopeHeaders`, or the three LAPI TLS fields. Middleware name, `next`, templates, trusted IPs, and Enabled MUST NOT be in that key. Live/none SHALL use `lapi:` plus `SessionHex` plus a hash of the identity payload (Redis store parameters and `MetricsUpdateIntervalSeconds`; not `IdentityHex` as the Open suffix). That live/none identity MUST still omit CAPI scenarios, `updateMaxFailure`, and `UpdateIntervalSeconds`. `IdentityHex` MAY stay exported for callers that still name it. `decisionScopeHeaders` MUST NOT be in any Client Open key. Stream `scopes=` is owned by `core_plugin_lapi_scope-union`. Live/none still pass scopes per `LiveLookup`. Cache prefix for the DecisionStore is owned by `core_cache_client_decision-store`. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP` (do not parse `RemoteAddr`). A second stream `New` on the same cursor plus Redis MUST `Open` that same key and MUST NOT `PeekLivePrefix` or warn-and-wire. Stream interval, CAPI scenario, and `updateMaxFailure` mismatch on a live sibling is silent first-wins (create already wrote those scalars). A second stream `New` that differs only on dropped fields SHALL reuse the same reclaim key and the same Client. A second live or none `New` that differs only on `MetricsUpdateIntervalSeconds` SHALL Open a sibling Client key and SHALL reuse the same DecisionStore key. A second `New` that differs on Redis store parameters SHALL Open a different Client key (and a different DecisionStore). Redis keys stay prefixed with `SessionHex`; changing the Client Open string MUST NOT migrate Redis keys.

#### Scenario: Same LAPI key two names share one stream
- **WHEN** two `New` calls use stream mode, the same LAPI URL and key, and different middleware names, each with a live constructor context
- **THEN** both bouncers use the same LAPI connection incarnation
- **AND** only one stream ticker is running for that session

#### Scenario: Same LAPI key different metrics interval shares one stream
- **WHEN** two live stream `New` calls use the same LAPI URL and key and the same Redis store parameters and differ only on `metricsUpdateIntervalSeconds` (or only `updateIntervalSeconds`)
- **THEN** both bouncers use the same LAPI connection
- **AND** only one `handleStreamCache` loop runs for that key
- **AND** no `PeekLivePrefix` warn-and-wire line is required

#### Scenario: None metrics interval splits the Client and keeps the store
- **WHEN** two none `New` calls use the same LAPI URL, key, and Redis store parameters and differ only on `metricsUpdateIntervalSeconds`
- **THEN** the two constructors receive different live/none `Key` values
- **AND** they receive the same `StoreKey`

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

#### Scenario: Different RedisCacheReadHosts isolate the Client
- **WHEN** two live stream `New` calls use the same LAPI URL and key and differ only on `RedisCacheReadHosts`
- **THEN** two LAPI connection incarnations exist
- **AND** two DecisionStore incarnations exist

#### Scenario: Header-map mismatch shares one stream
- **WHEN** two live stream `New` calls use the same LAPI URL, key, and Redis store parameters and differ only on `decisionScopeHeaders`
- **THEN** both bouncers use the same LAPI connection
- **AND** no warn-and-wire line is required

#### Scenario: Redis keys stay on SessionHex after the Open string changes
- **WHEN** DestBranch already prefixes Redis with `SessionHex` and this change only rewrites the in-process Client Open string
- **THEN** existing Redis keys stay reachable
- **AND** no Redis key migration runs

### Requirement: Snapshot change while sleeping opens a new reclaim key
When no live constructor context remains for a stream session and the previous slot is sleeping, a `New` with a **different** Redis store-parameters snapshot SHALL `Open` a new reclaim key (`lapi:stream:` plus `SessionHex` plus the new Redis hash). The sleeper SHALL remain until grace `Close()`. A `New` with the **same** Redis snapshot SHALL `Open` (Wake) without `startup=true`, even when intervals, CAPI scenarios, `updateMaxFailure`, or `decisionScopeHeaders` differ. Last holder SHALL `Sleep()` tickers before grace. Implementations MUST NOT call `Peek` or `PeekLivePrefix` to retitle a sleeper.

#### Scenario: Reload within grace Wakes
- **WHEN** every bound constructor context for a stream session is cancelled
- **AND** a `New` with the same session and same Redis store parameters runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`

#### Scenario: Redis host change does not overlap pollers
- **WHEN** the last holder of a stream session is cancelled
- **AND** a `New` for that session with a different `redisCacheHost` runs before grace ends
- **THEN** the previous ticker was already Sleep’d
- **AND** two `handleStreamCache` loops MUST NOT run on that session at once

#### Scenario: Sleeping interval change Wakes the same slot
- **WHEN** the last holder of a stream session is cancelled
- **AND** a `New` for that session with the same Redis store parameters and a different `updateIntervalSeconds` runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`

### Requirement: Unreclaimed LAPI Client is closed after grace
When no live constructor context remains for a LAPI connection key and grace elapses with no replace, the connection SHALL stop its tickers and release idle LAPI HTTP connections (`Close`). An `lapi.Client` SHALL wait 30 seconds (process table grace `ProcessGrace`). Open SHALL pass `reclaim.Hooks` for Sleep/Wake/Close.

#### Scenario: Connection grace is the process table wait
- **WHEN** the process table grace is 30 seconds
- **AND** the last holder of an `lapi.Client` is cancelled
- **THEN** the incarnation is still sleeping after 20 milliseconds
- **AND** it is disposed after 30 seconds
