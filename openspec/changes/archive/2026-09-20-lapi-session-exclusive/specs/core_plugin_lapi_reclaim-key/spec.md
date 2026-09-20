## MODIFIED Requirements

### Requirement: Stream session is LAPI URL plus bouncer key
For `stream` and `alone`, the session prefix SHALL be derived from mode, LAPI scheme/host/path and lapiKey (CAPI machine+password in alone). Intervals, Redis host/auth/db/read hosts, HTTP timeout, LAPI failure action, LAPI TLS extras, `StreamStartupBlock`, live-cache TTL, Redis fail-closed, and `decisionScopeHeaders` MUST NOT be in that prefix. AppSec host, key, TLS, and body limit MUST NOT be in the LAPI session prefix, LAPI Redis hash, or live/none LAPI identity. The LAPI reclaim `Open` key SHALL be `lapi:stream:` plus `SessionHex` plus a hash of Redis store parameters (`RedisCacheEnabled`, host, read hosts, password, database) — the same Redis payload family as today’s Client key, not a first-wins settings hash of intervals, `updateMaxFailure`, CAPI scenarios, or `decisionScopeHeaders`, and not the DecisionStore key. That hash MUST NOT include LAPI failure action, Redis fail-closed, live-cache TTL, `StreamStartupBlock`, HTTP timeout, intervals, CAPI scenarios, `updateMaxFailure`, `decisionScopeHeaders`, or the three LAPI TLS fields. Middleware name, `next`, templates, trusted IPs, and Enabled MUST NOT be in that key. Live/none SHALL use `lapi:` plus `SessionHex` plus a hash of the identity payload (Redis store parameters and `MetricsUpdateIntervalSeconds`; not `IdentityHex` as the Open suffix). That live/none identity MUST still omit CAPI scenarios, `updateMaxFailure`, and `UpdateIntervalSeconds`. `IdentityHex` MAY stay exported for callers that still name it. `decisionScopeHeaders` MUST NOT be in any Client Open key. Stream `scopes=` is owned by `core_plugin_lapi_scope-union`. Live/none still pass scopes per `LiveLookup`. Redis key prefix for the DecisionStore is owned by `core_plugin_decisionstore_store`. Client address, when this leaf mentions it, SHALL reuse `pkg/ip.GetRemoteIP` (do not parse `RemoteAddr`). Exclusive Traefik-name ownership of the DecisionStore is this leaf’s following requirement. A second stream `New` with the **same** Traefik name on the same cursor plus Redis MUST `Open` that same Client key and MUST NOT `PeekLivePrefix` or warn-and-wire. Stream interval, CAPI scenario, and `updateMaxFailure` mismatch on a live sibling with the same Traefik name is silent first-wins (create already wrote those scalars). A second stream `New` that differs only on dropped fields SHALL reuse the same reclaim key and the same Client when the Traefik name matches. A second live or none `New` that differs only on `MetricsUpdateIntervalSeconds` SHALL Open a sibling Client key and SHALL reuse the same DecisionStore key when the Traefik name matches. A second `New` that differs on Redis store parameters SHALL Open a different Client key and SHALL reuse the same DecisionStore when `SessionHex` matches and the Traefik name matches. Redis keys stay prefixed with `SessionHex`; changing the Client Open string MUST NOT migrate Redis keys.

#### Scenario: Same LAPI key two names fail the second New
- **WHEN** two `New` calls use stream mode, the same LAPI URL and key, and different Traefik middleware names, each with a live constructor context
- **THEN** the first constructor receives a DecisionStore and Client
- **AND** the second constructor returns an error and does not Open or Wake that store

#### Scenario: Same Traefik name many routers share one stream
- **WHEN** two `New` calls use stream mode, the same LAPI URL and key, and the same Traefik middleware name, each with a live constructor context
- **THEN** both bouncers use the same LAPI connection incarnation
- **AND** only one stream ticker is running for that session

#### Scenario: None metrics interval splits the Client and keeps the store
- **WHEN** two none `New` calls use the same Traefik name, the same LAPI URL, key, and Redis store parameters and differ only on `metricsUpdateIntervalSeconds`
- **THEN** the two constructors receive different live/none `Key` values
- **AND** they receive the same `StoreKey`

### Requirement: Snapshot change while sleeping opens a new reclaim key
When no live constructor context remains for a stream session and the previous slot is sleeping, a `New` with the **same** Traefik name and a **different** Redis store-parameters snapshot SHALL `Open` a new Client reclaim key (`lapi:stream:` plus `SessionHex` plus the new Redis hash) and SHALL Open (bind/Wake) the existing DecisionStore for that `SessionHex`. The Client sleeper SHALL remain until grace `Close()`. A `New` with the **same** Traefik name and the **same** Redis snapshot SHALL `Open` (Wake) the Client without `startup=true`, even when intervals, CAPI scenarios, `updateMaxFailure`, or `decisionScopeHeaders` differ. Last holder SHALL `Sleep()` tickers before grace. Implementations MUST NOT call `PeekLivePrefix` or Peek a Client key to retitle a sleeper. Exact Peek of the DecisionStore key is required by the exclusive-name requirement.

#### Scenario: Reload within grace Wakes
- **WHEN** every bound constructor context for a stream session is cancelled
- **AND** a `New` with the same Traefik name, same session, and same Redis store parameters runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`

#### Scenario: Redis host change does not overlap pollers
- **WHEN** the last holder of a stream session is cancelled
- **AND** a `New` for that session with the same Traefik name and a different `redisCacheHost` runs before grace ends
- **THEN** the previous ticker was already Sleep’d
- **AND** two `handleStreamCache` loops MUST NOT run on that session at once

#### Scenario: Sleeping interval change Wakes the same slot
- **WHEN** the last holder of a stream session is cancelled
- **AND** a `New` for that session with the same Traefik name, the same Redis store parameters, and a different `updateIntervalSeconds` runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling resumes with `startup=false`

## ADDED Requirements

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
