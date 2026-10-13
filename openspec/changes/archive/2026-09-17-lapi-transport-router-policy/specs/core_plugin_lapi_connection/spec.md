## MODIFIED Requirements

### Requirement: LAPI named files stay job-owned
`package lapi` SHALL keep `Client` construct/close in `client.go` and SHALL place stream ticker, live lookup, LAPI/CAPI HTTP, and metrics in `client_stream.go`, `client_live.go`, `client_http.go`, and `client_metrics.go` respectively. Reclaim identity SHALL stay in `identity.go`. Stream store/delete and live decision parse SHALL stay in `client_decisions.go`. LAPI HTTP, request headers, and CAPI token SHALL live as an unexported `transport` in `client_http.go`. The Client field that holds that transport SHALL be `atomic.Value` (not `atomic.Pointer[T]`).

#### Scenario: Named LAPI files exist
- **WHEN** a developer opens `pkg/lapi/`
- **THEN** `client_stream.go`, `client_live.go`, `client_http.go`, and `client_metrics.go` exist
- **AND** `LiveLookup` is declared in `client_live.go`
- **AND** `pkg/lapi/connection_appsec.go` does not exist
- **AND** `transport` is declared in `client_http.go`

## ADDED Requirements

### Requirement: LAPI HTTP transport is replaceable after Open
`Client` SHALL store LAPI HTTP+auth (including CAPI token) as `atomic.Value`. After `OpenStream` or `OpenLive` bind, the constructor SHALL call `AdoptTransport` with that config: Store the new transport and idle-close the previous HTTP client. Remaining write-once Client scalar fields MUST NOT become mutable. `getToken` SHALL write the CAPI token on the stored transport, not on a write-once Client key field.

#### Scenario: AdoptTransport replaces HTTP without a new Client
- **WHEN** a later `New` reuses a live Client and calls `AdoptTransport` with a different TLS or HTTP timeout
- **THEN** later LAPI requests use the new HTTP client
- **AND** the previous HTTP client’s idle connections are closed
- **AND** an INFO line names the replaced transport fields

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
