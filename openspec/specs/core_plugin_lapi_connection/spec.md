## Purpose

`package lapi` owns the reclaim value for CrowdSec LAPI/CAPI decisions (`lapi.Client`). It does not own AppSec.

## Requirements

### Requirement: LAPI lives in package lapi
`package lapi` SHALL own the reclaim value for CrowdSec LAPI/CAPI decisions. The exported type SHALL be `Client`. The package MUST NOT import `pkg/appsec` and MUST NOT export AppSec query, envelope, or AppSec HTTP-client types. Callers SHALL import `pkg/lapi` for `Prepare`, `New`, `OpenStream`, `OpenLive`, `Client`, `LiveLookup`, `Key`, `IdentityHex`, `SessionKey`, and usage-metrics increments.

#### Scenario: Bouncer looks up decisions on lapi
- **WHEN** `pkg/bouncer` compiles against this package
- **THEN** `lapi.Client.LiveLookup` resolves
- **AND** `AppsecQuery` is not a method on `lapi.Client`

### Requirement: LAPI named files stay job-owned
`package lapi` SHALL keep `Client` construct/close in `client.go` and SHALL place stream ticker, live lookup, LAPI/CAPI HTTP, and metrics in `client_stream.go`, `client_live.go`, `client_http.go`, and `client_metrics.go` respectively. Reclaim identity SHALL stay in `identity.go`. Stream store/delete and live decision parse SHALL stay in `client_decisions.go`. LAPI HTTP, request headers, and CAPI token SHALL live as an unexported `transport` in `client_http.go`. The Client field that holds that transport SHALL be `atomic.Value` (not `atomic.Pointer[T]`).

#### Scenario: Named LAPI files exist
- **WHEN** a developer opens `pkg/lapi/`
- **THEN** `client_stream.go`, `client_live.go`, `client_http.go`, and `client_metrics.go` exist
- **AND** `LiveLookup` is declared in `client_live.go`
- **AND** `pkg/lapi/connection_appsec.go` does not exist
- **AND** `transport` is declared in `client_http.go`

### Requirement: Stream poll ticks stay at DEBUG
A stream poll SHALL emit `handleStreamTicker:poll` when it wins the in-flight CAS and SHALL emit `handleStreamCache:updated` after a successful LAPI fetch and apply. A busy tick SHALL emit `handleStreamTicker:skip` and MUST NOT GET stream. Those three messages MUST be DEBUG. They MUST NOT appear when the plugin logger is at the default INFO level. `handleStreamTicker:poll` and `handleStreamCache:updated` SHALL carry `sessionKey`, `startup`, and `fetches`; `updated` SHALL also carry payload `new` and `deleted` counts and `durationMs`. There is no stream lease and no `handleStreamCache:alreadyUpdated` line. Stream health transitions (`crowdsec stream became healthy` / `crowdsec stream became unhealthy`) remain INFO and are not this requirement.

#### Scenario: Successful poll does not INFO-spam
- **WHEN** stream mode polls LAPI and the fetch succeeds
- **THEN** `handleStreamTicker:poll` and `handleStreamCache:updated` are present at DEBUG
- **AND** those messages are absent when the logger is at INFO

#### Scenario: Busy tick does not INFO-spam
- **WHEN** stream mode ticks while a poll is already in flight
- **THEN** `handleStreamTicker:skip` is present at DEBUG
- **AND** that message is absent when the logger is at INFO
- **AND** the tick does not GET stream

### Requirement: LAPI HTTP transport is replaceable after Open
`Client` SHALL store LAPI HTTP+auth (including CAPI token) as `atomic.Value`. After `OpenStream` or `OpenLive` bind, the constructor SHALL call `AdoptTransport` with that config: Store the new transport and idle-close the previous HTTP client. Concurrent replaces SHALL last-write the stored transport and idle-close the value they replaced. Remaining write-once Client scalar fields MUST NOT become mutable. `getToken` SHALL write the CAPI token on the stored transport, not on a write-once Client key field.

#### Scenario: AdoptTransport replaces HTTP without a new Client
- **WHEN** a later `New` reuses a live Client and calls `AdoptTransport` with a different TLS or HTTP timeout
- **THEN** later LAPI requests use the new HTTP client
- **AND** the previous HTTP client’s idle connections are closed
- **AND** an INFO line names the replaced transport fields

#### Scenario: Concurrent transport replace last-writes
- **WHEN** two constructors call transport replace on the same Client
- **THEN** the Client’s subsequent LAPI HTTP uses one of those transports
- **AND** the replaced HTTP client’s idle connections are closed

### Requirement: LiveLookup TTL is passed by the caller
`LiveLookup` SHALL take `defaultDecisionSeconds` from the caller. `Client` MUST NOT store `defaultDecisionTimeout`. The bouncer SHALL pass `config.DefaultDecisionSeconds`.

#### Scenario: Bouncer supplies live TTL
- **WHEN** a live-mode request misses cache and LAPI returns no active remediation
- **THEN** the cache write uses the TTL that bouncer passed, not a field on Client

### Requirement: Lifecycle INFO includes session key and reason
`logInfo` SHALL include the reclaim session key (`SessionKey` for stream/alone, `Key` for live/none) and a `reason` field. Existing lifecycle reasons SHALL stay `started|sleeping|waking|closed`. New INFO lines SHALL name transport replace and a live joiner whose remaining settings differ (`ignored` vs `adopted`). `reclaim_put`, `reclaim_reclaim`, and `reclaim_dispose` MUST stay DEBUG.

#### Scenario: Lifecycle line carries key and reason
- **WHEN** a Client starts
- **THEN** the INFO line includes the reclaim key and `reason=started`
- **AND** `reclaim_put` is absent at INFO

### Requirement: CAPI login stores a non-empty token after HTTP 2xx
After the CAPI `watchers/login` exchange returns HTTP 2xx, `getToken` SHALL store the login body's `token` on the stored transport when that string is non-empty. HTTP 2xx is already owned by `sendQuery`. JSON `code` MUST NOT be consulted as a success gate. When `token` is empty, `getToken` SHALL keep the existing `getToken statusCode:` error, including when JSON `code` is omitted (Go zero `0`). `Login` struct tags, expire parsing, CAPI host/route, 401 replay, and connection drain MUST NOT change.

#### Scenario: 2xx body with token and no JSON code
- **WHEN** CAPI login answers HTTP 2xx with body `{"token":"fresh","expire":"later"}` and no `code`
- **THEN** `getToken` returns nil
- **AND** the stored transport key is `fresh`

#### Scenario: 2xx body with empty token
- **WHEN** CAPI login answers HTTP 2xx with an empty `token`
- **THEN** `getToken` returns an error whose message starts with `getToken statusCode:`

#### Scenario: 2xx body with token and non-200 JSON code
- **WHEN** CAPI login answers HTTP 2xx with a non-empty `token` and a JSON `code` that is not 200
- **THEN** `getToken` stores that token on the stored transport

### Requirement: LAPI transport Timeout is the effective LAPI seconds
LAPI HTTP construct SHALL set `http.Client.Timeout` and the stored timeout seconds from `config.EffectiveHTTPTimeoutSeconds(config.CrowdsecLapiHTTPTimeoutSeconds)`. It MUST NOT read raw `HTTPTimeoutSeconds` when the LAPI override is non-zero. `AdoptTransport` SHALL keep last-writing that transport on the same Client. A later `New` that changes only the effective LAPI seconds SHALL Adopt, not Open a new Client.

#### Scenario: LAPI override adopts Timeout
- **WHEN** a live stream Client exists with `HTTPTimeoutSeconds` 10 and LAPI override 0
- **AND** a later `New` for the same LAPI URL and key sets `CrowdsecLapiHTTPTimeoutSeconds` to 30
- **THEN** both constructors receive the same Client
- **AND** the stored transport Timeout is 30 seconds
- **AND** the stored `httpTimeoutSeconds` is 30

#### Scenario: Shared-default change adopts when override is still zero
- **WHEN** a live stream Client exists with `HTTPTimeoutSeconds` 10 and LAPI override 0
- **AND** a later `New` for the same LAPI URL and key sets `HTTPTimeoutSeconds` to 20 and leaves the LAPI override 0
- **THEN** both constructors receive the same Client
- **AND** the stored transport Timeout is 20 seconds

#### Scenario: Override zero and override equal to shared do not replace
- **WHEN** a live stream Client exists with `HTTPTimeoutSeconds` 10 and LAPI override 0
- **AND** a later `New` for the same LAPI URL and key sets `CrowdsecLapiHTTPTimeoutSeconds` to 10
- **THEN** both constructors receive the same Client
- **AND** the Client does not replace the HTTP client for a timeout-only no-op
