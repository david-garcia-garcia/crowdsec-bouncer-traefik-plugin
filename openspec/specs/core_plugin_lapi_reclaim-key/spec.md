## Purpose

How this plugin keys a reclaimed `lapi.Client`: the stream/alone `Open` key is `lapi:stream:` plus `SessionHex` plus a hash of Redis store parameters, so routers that share one CrowdSec cursor row, one Redis, and one Traefik name share one Client even when intervals or `lapiScopeHeaders` differ; live/none `Key` is `lapi:` plus `SessionHex` plus a hash of the identity payload (Redis store parameters and `LapiMetricsIntervalSeconds`). A second Traefik name on the same DecisionStore Peek-fails before Open. Exact Peek of the store key is required; there is no `PeekLivePrefix`. An unreclaimed Client waits process-table `ProcessGrace` 30s. Redis keys stay prefixed with `SessionHex`, so changing an Open key never migrates cache.

## Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, the session prefix SHALL be derived from mode, LAPI scheme/host/path and lapiKey (CAPI machine+password in alone). Intervals, Redis host/auth/db/read hosts, HTTP timeout, LAPI failure action, LAPI TLS extras, `LapiStreamStartupBlock`, live-cache TTL, Redis fail-closed, and `lapiScopeHeaders` MUST NOT be in that prefix. AppSec host, key, TLS, and body limit MUST NOT be in the LAPI session prefix, LAPI Redis hash, or live/none LAPI identity. The LAPI reclaim `Open` key SHALL be `lapi:stream:` plus `SessionHex` plus a hash of Redis store parameters (`LapiRedisEnabled`, host, read hosts, password, database) — the same Redis payload family as today’s Client key, not a first-wins settings hash of intervals, `lapiUpdateMaxFailure`, CAPI scenarios, or `lapiScopeHeaders`, and not the DecisionStore key. That hash MUST NOT include LAPI failure action, Redis fail-closed, live-cache TTL, `LapiStreamStartupBlock`, HTTP timeout, intervals, CAPI scenarios, `lapiUpdateMaxFailure`, `lapiScopeHeaders`, or the three LAPI TLS fields. Middleware name, `next`, templates, trusted IPs, and Enabled MUST NOT be in that key. Live/none SHALL use `lapi:` plus `SessionHex` plus a hash of the identity payload (Redis store parameters and `LapiMetricsIntervalSeconds`; not `IdentityHex` as the Open suffix). That live/none identity MUST still omit CAPI scenarios, `lapiUpdateMaxFailure`, and `LapiUpdateIntervalSeconds`. `IdentityHex` MAY stay exported for callers that still name it. `lapiScopeHeaders` MUST NOT be in any Client Open key. Stream `scopes=` is owned by `core_plugin_lapi_scope-union`. Live/none still pass scopes per `LiveLookup`. Redis key prefix for the DecisionStore is owned by `core_plugin_decisionstore_store`. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP` (do not parse `RemoteAddr`). Exclusive ownership of the DecisionStore SHALL use the LAPI instance name (`lapiInstance`, or Traefik `New` name when that field is empty), not a bouncing subscriber's Traefik name. Same instance name on many Openers MUST share. A different instance name on the same SessionHex SHALL fail `New` before Open.

#### Scenario: Same LAPI key two instance names fail the second New
- **WHEN** two Open `New` calls use stream mode, the same LAPI URL and key, and different `lapiInstance` values, each with a live constructor context
- **THEN** the first constructor receives a DecisionStore and Client
- **AND** the second constructor returns an error and does not Open or Wake that store

#### Scenario: Same instance name many Openers share one stream
- **WHEN** two Open `New` calls use stream mode, the same LAPI URL and key, and the same `lapiInstance`, each with a live constructor context
- **THEN** both receive the same LAPI connection incarnation
- **AND** only one stream ticker is running for that session

#### Scenario: None metrics interval splits the Client and keeps the store
- **WHEN** two none `New` calls use the same Traefik name, the same LAPI URL, key, and Redis store parameters and differ only on `lapiMetricsIntervalSeconds`
- **THEN** the two constructors receive different live/none `Key` values
- **AND** they receive the same `StoreKey`

### Requirement: Snapshot change while sleeping opens a new reclaim key
When no live constructor context remains for a stream session and the previous slot is sleeping, a `New` with the **same** Traefik name and a **different** Redis store-parameters snapshot SHALL `Open` a new Client reclaim key (`lapi:stream:` plus `SessionHex` plus the new Redis hash) and SHALL Open (bind/Wake) the existing DecisionStore for that `SessionHex`. The Client sleeper SHALL remain until grace `Close()`. A `New` with the **same** Traefik name and the **same** Redis snapshot SHALL `Open` (Wake) the Client without `startup=true`, even when intervals, CAPI scenarios, `lapiUpdateMaxFailure`, or `lapiScopeHeaders` differ. Last holder SHALL `Sleep()` tickers before grace. Implementations MUST NOT call `PeekLivePrefix` or Peek a Client key to retitle a sleeper. Exact Peek of the DecisionStore key is required by the exclusive-name requirement.

#### Scenario: Reload within grace Wakes
- **WHEN** every bound constructor context for a stream session is cancelled
- **AND** a `New` with the same Traefik name, same session, and same Redis store parameters runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`

#### Scenario: Redis host change does not overlap pollers
- **WHEN** the last holder of a stream session is cancelled
- **AND** a `New` for that session with the same Traefik name and a different `lapiRedisHost` runs before grace ends
- **THEN** the previous ticker was already Sleep’d
- **AND** two `handleStreamCache` loops MUST NOT run on that session at once

#### Scenario: Sleeping interval change Wakes the same slot
- **WHEN** the last holder of a stream session is cancelled
- **AND** a `New` for that session with the same Traefik name, the same Redis store parameters, and a different `lapiUpdateIntervalSeconds` runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`

### Requirement: Exclusive Traefik name owns the DecisionStore session
`OpenStream` and `OpenLive` SHALL Peek the DecisionStore reclaim key before Open. The Traefik Yaegi `New(..., name)` string is the identity; implementations MUST NOT reconstruct it from router name, Host, or a second registry, and MUST NOT put it in a reclaim key. Peek hit and store `createdBy` not equal to this name SHALL return an error, MUST NOT Open, and MUST NOT Wake. Peek miss or `createdBy` equal to this name SHALL Open the store (bind/Wake). An empty name SHALL still exclusive-own the store: two empty names share; a non-empty name SHALL fail Peek against empty `createdBy`. Peek `ok=false` (missing, gone, or busy) SHALL proceed to Open only for the miss-or-same-name path from a non-busy Peek; a busy Peek SHALL NOT wait. Parallel-create of two different names is out of scope; implementations MUST NOT add a post-Open `createdBy` check. The error and an operator Error log SHALL name the owner, the rejected name, that the lock clears when the old slot Closes, and that isolation is a second bouncer API key (or a different LAPI host), not a second middleware on the same key. Rename during process-table grace SHALL keep failing until the sleeper Closes; Traefik retry after Close SHALL succeed for the new name. Failed `New` SHALL still cancel `plugin.go` bindCtx. Live/none SHALL use the same exclusive-name rule and SHALL preserve the store; they have no stream startup flag. Implementations MUST NOT call `PeekLivePrefix`. Client Close MUST NOT Close the store.

#### Scenario: Different names fail before store Open
- **WHEN** a live stream store exists with `createdBy` `foo`
- **AND** a later `New` for the same LAPI URL and key uses Traefik name `bar`
- **THEN** Peek returns that store without binding
- **AND** `New` returns an error naming `foo` and `bar`
- **AND** the store holder count is unchanged
- **AND** the store is not Woken

#### Scenario: Same name during grace Wakes the store
- **WHEN** the last holder of a stream DecisionStore is cancelled and the slot is sleeping
- **AND** a `New` with the same Traefik name and same `SessionHex` runs before grace ends
- **THEN** Peek sees `createdBy` equal to that name
- **AND** Open Wakes the same store

#### Scenario: Empty name still exclusive-owns
- **WHEN** the first `New` uses an empty Traefik name and creates the store
- **AND** a later `New` for the same `SessionHex` uses a non-empty Traefik name
- **THEN** the second `New` returns an error
- **AND** two later `New` calls that both use the empty name share that store

### Requirement: Unreclaimed LAPI Client is closed after grace
When no live constructor context remains for a LAPI connection key and grace elapses with no replace, the connection SHALL stop its tickers and release idle LAPI HTTP connections (`Close`). An `lapi.Client` SHALL wait 30 seconds (process table grace `ProcessGrace`). Open SHALL pass `reclaim.Hooks` for Sleep/Wake/Close.

#### Scenario: Connection grace is the process table wait
- **WHEN** the process table grace is 30 seconds
- **AND** the last holder of an `lapi.Client` is cancelled
- **THEN** the incarnation is still sleeping after 20 milliseconds
- **AND** it is disposed after 30 seconds

### Requirement: Inherit HTTP timeout knobs stay out of LAPI reclaim identity
Stream/alone `SessionKey`, live/none `Key`, and `IdentityHex` MUST NOT include `LapiHttpTimeoutSeconds`, `AppsecHttpTimeoutSeconds`, or `BouncerCaptchaHttpTimeoutSeconds`. Composition SHALL reuse those existing owners. Those owners MUST NOT gain timeout knobs or effective seconds.

#### Scenario: Timeout knobs only do not change stream or live keys
- **WHEN** two stream configs share LAPI URL, key, and Redis store parameters and differ only on `HTTPTimeoutSeconds` or any of the three inherit timeout knobs
- **THEN** `SessionKey` is the same
- **AND** `IdentityHex` is the same
- **AND** live/none `Key` is the same
