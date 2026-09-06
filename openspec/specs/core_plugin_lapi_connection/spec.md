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
`package lapi` SHALL keep `Client` construct/close in `client.go` and SHALL place stream ticker, live lookup, LAPI/CAPI HTTP, and metrics in `client_stream.go`, `client_live.go`, `client_http.go`, and `client_metrics.go` respectively. Reclaim identity SHALL stay in `identity.go`. Stream store/delete and live decision parse SHALL stay in `client_decisions.go`.

#### Scenario: Named LAPI files exist
- **WHEN** a developer opens `pkg/lapi/`
- **THEN** `client_stream.go`, `client_live.go`, `client_http.go`, and `client_metrics.go` exist
- **AND** `LiveLookup` is declared in `client_live.go`
- **AND** `pkg/lapi/connection_appsec.go` does not exist

### Requirement: Stream poll ticks stay at DEBUG
Successful stream cache ticks SHALL emit `handleStreamCache:updated` after a LAPI fetch and `handleStreamCache:alreadyUpdated` when the stream lease is already held. Both messages MUST be DEBUG. They MUST NOT appear when the plugin logger is at the default INFO level. Stream health transitions (`crowdsec stream became healthy` / `crowdsec stream became unhealthy`) remain INFO and are not this requirement.

#### Scenario: Lease miss does not INFO-spam
- **WHEN** stream mode polls LAPI because the stream lease is missing and the fetch succeeds
- **THEN** `handleStreamCache:updated` is present at DEBUG
- **AND** that message is absent when the logger is at INFO

#### Scenario: Lease hit does not INFO-spam
- **WHEN** stream mode ticks while the stream lease is already held
- **THEN** `handleStreamCache:alreadyUpdated` is present at DEBUG
- **AND** that message is absent when the logger is at INFO

### Requirement: LAPI HTTP timeout inherits HTTPTimeoutSeconds
Public config `crowdsecLapiHttpTimeoutSeconds` SHALL be an integer second timeout for the LAPI HTTP client. Zero or omit SHALL use `httpTimeoutSeconds`. A value greater than zero SHALL be that many seconds. A negative value SHALL be rejected at ValidateParams. Live/none reclaim identity and stream settings SHALL hash the effective LAPI timeout, not the raw fallback field.

#### Scenario: Omit inherits HTTPTimeoutSeconds
- **WHEN** the operator omits `crowdsecLapiHttpTimeoutSeconds` and sets `httpTimeoutSeconds` to 10
- **THEN** LAPI HTTP calls use a 10 second timeout

#### Scenario: Explicit seconds override HTTPTimeoutSeconds
- **WHEN** the operator sets `crowdsecLapiHttpTimeoutSeconds` to 30 and `httpTimeoutSeconds` to 10
- **THEN** LAPI HTTP calls use a 30 second timeout

#### Scenario: Same effective timeout shares live identity
- **WHEN** one middleware inherits a 10 second LAPI timeout from `httpTimeoutSeconds` and another sets `crowdsecLapiHttpTimeoutSeconds` to 10
- **THEN** both use the same live/none LAPI identity hash
