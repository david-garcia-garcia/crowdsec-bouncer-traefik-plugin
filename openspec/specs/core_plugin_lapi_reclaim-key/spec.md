## Purpose

How this plugin keys a reclaimed `lapi.Client`: the stream/alone `Open` key is `lapi:stream:` plus `SessionHex` (mode + LAPI scheme/host/path + lapiKey), so routers that share one CrowdSec cursor row share one Client even when Redis or intervals differ; live/none `Key` is `lapi:` plus `SessionHex` plus a hash of the identity payload (Redis store parameters and `MetricsUpdateIntervalSeconds`), so a metrics-interval mismatch Opens a sibling Client. A second stream `New` on the same session Opens that same key (subscribe or Wake) with first-wins WARN for session-owned knobs; there is no `PeekLivePrefix`. An unreclaimed Client waits process-table `ProcessGrace` 30s. Redis keys stay prefixed with `SessionHex`, so changing an Open key never migrates cache.

## Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, the session prefix SHALL be derived from mode, LAPI scheme/host/path and lapiKey (CAPI machine+password in alone). Intervals, Redis host/auth/db/read hosts, HTTP timeout, LAPI failure action, LAPI TLS extras, `StreamStartupBlock`, live-cache TTL, Redis fail-closed, and `decisionScopeHeaders` MUST NOT be in that prefix. AppSec host, key, TLS, and body limit MUST NOT be in the LAPI session prefix or live/none LAPI identity. The LAPI reclaim `Open` key SHALL be `lapi:stream:` plus `SessionHex` and MUST NOT include a hash of Redis store parameters, middleware name, outbound IP, or LAPI host alone. Two LAPI keys on one host SHALL stay two Clients. That key MUST NOT include LAPI failure action, Redis fail-closed, live-cache TTL, `StreamStartupBlock`, HTTP timeout, intervals, CAPI scenarios, `updateMaxFailure`, `decisionScopeHeaders`, Redis store parameters, or the three LAPI TLS fields. Middleware name, `next`, templates, trusted IPs, and Enabled MUST NOT be in that key. Live/none SHALL use `lapi:` plus `SessionHex` plus a hash of the identity payload (Redis store parameters and `MetricsUpdateIntervalSeconds`; not `IdentityHex` as the Open suffix). That live/none identity MUST still omit CAPI scenarios, `updateMaxFailure`, and `UpdateIntervalSeconds`. `IdentityHex` MAY stay exported for callers that still name it. `decisionScopeHeaders` MUST NOT be in any Client Open key. Stream `scopes=` is owned by `core_plugin_lapi_scope-union`. Live/none still pass scopes per `LiveLookup`. Redis key prefix for the DecisionStore is owned by `core_plugin_decisionstore_store`. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP` (do not parse `RemoteAddr`). A second stream `New` on the same session MUST `Open` that same key and MUST NOT `PeekLivePrefix`, warn-and-wire, or fail `New`. Stream Redis, interval, CAPI scenario, `metricsUpdateIntervalSeconds`, and `updateMaxFailure` mismatch on a live sibling is first-wins with WARN (owned by this leaf’s subscribe requirement). A second stream `New` that differs only on dropped fields SHALL reuse the same reclaim key and the same Client. A second live or none `New` that differs only on `MetricsUpdateIntervalSeconds` SHALL Open a sibling Client key. A second stream `New` that differs on Redis store parameters SHALL reuse the same Client key and the same Client. A second live or none `New` that differs on Redis store parameters SHALL Open a different Client key. Redis keys stay prefixed with `SessionHex`; changing the Client Open string MUST NOT migrate Redis keys.

#### Scenario: Same LAPI key two names share one stream
- **WHEN** two `New` calls use stream mode, the same LAPI URL and key, and different middleware names, each with a live constructor context
- **THEN** both bouncers use the same LAPI connection incarnation
- **AND** only one stream ticker is running for that session

#### Scenario: Different Redis shares one stream Client
- **WHEN** two stream `New` calls use the same LAPI URL and key and different `redisCacheHost`, each with a live constructor context
- **THEN** both constructors receive the same `SessionKey`
- **AND** both bouncers use the same Client
- **AND** only one stream ticker is running for that session

#### Scenario: Two LAPI keys on one host stay two Clients
- **WHEN** two stream `New` calls use the same LAPI scheme, host, and path and different lapiKeys
- **THEN** they Open different `SessionKey` values
- **AND** two stream tickers run

#### Scenario: None metrics interval splits the Client
- **WHEN** two none `New` calls use the same LAPI URL, key, and Redis store parameters and differ only on `metricsUpdateIntervalSeconds`
- **THEN** the two constructors receive different live/none `Key` values

### Requirement: Unreclaimed LAPI Client is closed after grace
When no live constructor context remains for a LAPI connection key and grace elapses with no replace, the connection SHALL stop its tickers and release idle LAPI HTTP connections (`Close`). An `lapi.Client` SHALL wait 30 seconds (process table grace `ProcessGrace`). Open SHALL pass `reclaim.Hooks` for Sleep/Wake/Close.

#### Scenario: Connection grace is the process table wait
- **WHEN** the process table grace is 30 seconds
- **AND** the last holder of an `lapi.Client` is cancelled
- **THEN** the incarnation is still sleeping after 20 milliseconds
- **AND** it is disposed after 30 seconds

### Requirement: Inherit HTTP timeout knobs stay out of LAPI reclaim identity
Stream/alone `SessionKey`, live/none `Key`, and `IdentityHex` MUST NOT include `CrowdsecLapiHTTPTimeoutSeconds`, `CrowdsecAppsecHTTPTimeoutSeconds`, or `CaptchaSiteverifyHTTPTimeoutSeconds`. Composition SHALL reuse those existing owners. Those owners MUST NOT gain timeout knobs or effective seconds.

#### Scenario: Timeout knobs only do not change stream or live keys
- **WHEN** two stream configs share LAPI URL, key, and Redis store parameters and differ only on `HTTPTimeoutSeconds` or any of the three inherit timeout knobs
- **THEN** `SessionKey` is the same
- **AND** `IdentityHex` is the same
- **AND** live/none `Key` is the same

### Requirement: Subscribe WARNs ignored session-owned knobs
When `OpenStream` or `OpenLive` returns an existing Client (`create` did not run: live bind or Wake), the constructor SHALL compare the joiner YAML against create-time residue captured at `create()`. On any difference among `redisCacheEnabled`, `redisCacheHost`, `redisCachePassword`, `redisCacheDatabase`, `redisCacheReadHosts`, `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, and CAPI scenarios (`crowdsecCapiScenarios`), the constructor SHALL emit WARN listing every ignored field name, the distinct live holder middleware names, and that isolation requires a second bouncer API key. WARN MUST name fields, not secret values (`redisCachePassword` SHALL appear as a field name only). The constructor MUST NOT fail `New`. TLS and HTTP timeout MUST NOT appear on that WARN (`AdoptTransport` last-wins is owned by `core_plugin_lapi_connection`). `decisionScopeHeaders` MUST NOT appear on that WARN (live union is owned by `core_plugin_lapi_scope-union`). Per-router Bouncer knobs (failure actions, templates, trusted IPs, Enabled, captcha) MUST NOT appear. When those session-owned knobs match, the constructor MUST NOT emit that WARN.

#### Scenario: Live stream Redis mismatch WARNs and shares
- **WHEN** a live stream Client exists for a LAPI session
- **AND** a second stream `New` uses the same LAPI URL and key and a different `redisCacheHost`
- **THEN** both constructors receive the same Client
- **AND** a WARN lists `redisCacheHost`, the distinct holder middleware names, and that isolation requires a second bouncer API key
- **AND** `New` returns the handler without error

#### Scenario: Live interval mismatch WARNs and shares
- **WHEN** a live stream Client exists for a LAPI session
- **AND** a second stream `New` uses the same LAPI URL and key and a different `updateIntervalSeconds`
- **THEN** both constructors receive the same Client
- **AND** a WARN lists `updateIntervalSeconds`, the distinct holder middleware names, and that isolation requires a second bouncer API key
- **AND** the running ticker keeps the create-time interval

### Requirement: Holder middleware names are a constructor-ctx set
A stream or live `lapi.Client` SHALL hold a Client-owned registry of Traefik middleware names keyed by constructor context (the same shape as live header-scope registration). After a successful `OpenStream` or `OpenLive` bind, the constructor SHALL register this `New` ctx and this Traefik `name`. When that ctx is Done, the Client SHALL drop that registration. WARN of ignored session-owned knobs SHALL print the distinct names (a set). Two routers with the same middleware alias SHALL be two contexts and one name. Implementations MUST NOT store a single `ownerName` in place of the set. Implementations MUST NOT use `Peek` or `PeekLivePrefix`. Implementations MUST NOT use `atomic.Pointer[T]`, `sync.Once`, or a package global for this registry.

#### Scenario: Two routers one alias one name
- **WHEN** two live stream `New` calls share one Client and pass the same Traefik middleware name
- **THEN** the holder registry has two constructor contexts
- **AND** the distinct names printed on a subscribe WARN contain that name once

#### Scenario: Distinct names appear on WARN
- **WHEN** two live stream `New` calls share one Client, pass different Traefik middleware names, and disagree on `updateIntervalSeconds`
- **THEN** the WARN lists both middleware names

### Requirement: Sleeping stream New Wakes the same session
When no live constructor context remains for a stream session and the previous slot is sleeping, a `New` with the same `SessionHex` SHALL `Open` (Wake) that key without `startup=true`, even when Redis store parameters, intervals, CAPI scenarios, `updateMaxFailure`, or `decisionScopeHeaders` differ. Last holder SHALL `Sleep()` tickers before grace. Implementations MUST NOT call `Peek` or `PeekLivePrefix` to retitle a sleeper. A Redis YAML change on Wake SHALL keep the live DecisionStore and SHALL WARN the ignored Redis fields; it MUST NOT migrate memory↔Redis and MUST NOT Open a second ticker on that session.

#### Scenario: Reload within grace Wakes
- **WHEN** every bound constructor context for a stream session is cancelled
- **AND** a `New` with the same session runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`

#### Scenario: Redis host change Wakes the same slot
- **WHEN** the last holder of a stream session is cancelled
- **AND** a `New` for that session with a different `redisCacheHost` runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`
- **AND** the live DecisionStore is the store that `create()` opened
- **AND** a WARN lists the ignored Redis fields
- **AND** two `handleStreamCache` loops MUST NOT run on that session at once

#### Scenario: Sleeping interval change Wakes the same slot
- **WHEN** the last holder of a stream session is cancelled
- **AND** a `New` for that session with a different `updateIntervalSeconds` runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`

### Requirement: README names ignored Redis and interval
The README shared-session Note SHALL say that one LAPI key in this Traefik instance is one stream ticker and one usage-metrics window, that Redis and interval disagreements are ignored rather than isolated, and that a second isolated backend needs a different bouncer API key. It SHALL say reclaim is process-local: two Traefik processes that share a key still run two tickers (docs only). It MAY say stream and live on the same key still POST two metrics windows.

#### Scenario: Note denies Redis isolation
- **WHEN** an operator reads the README shared-session Note
- **THEN** the Note states that Redis and interval disagreements on one LAPI key are ignored, not isolated
- **AND** the Note states that isolation needs a different LAPI key
