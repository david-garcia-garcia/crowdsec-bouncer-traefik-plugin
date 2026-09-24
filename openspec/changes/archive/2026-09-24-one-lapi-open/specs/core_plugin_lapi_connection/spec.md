## MODIFIED Requirements

### Requirement: LAPI lives in package lapi
`package lapi` SHALL own the reclaim value for CrowdSec LAPI/CAPI decisions. The exported type SHALL be `Client`. The package MUST NOT import `pkg/appsec` and MUST NOT export AppSec query, envelope, or AppSec HTTP-client types. Callers SHALL import `pkg/lapi` for `Prepare`, `New`, `Open`, `Client`, `LiveLookup`, `Key`, `IdentityHex`, `SessionKey`, and usage-metrics increments.

#### Scenario: Bouncer looks up decisions on lapi
- **WHEN** `pkg/bouncer` compiles against this package
- **THEN** `lapi.Client.LiveLookup` resolves
- **AND** `AppsecQuery` is not a method on `lapi.Client`

### Requirement: LAPI HTTP transport is replaceable after Open
`Client` SHALL store LAPI HTTP+auth (including CAPI token) as `atomic.Value`. After `Open` bind, the constructor SHALL call `AdoptTransport` with that config: Store the new transport and idle-close the previous HTTP client. Concurrent replaces SHALL last-write the stored transport and idle-close the value they replaced. Remaining write-once Client scalar fields MUST NOT become mutable. `getToken` SHALL write the CAPI token on the stored transport, not on a write-once Client key field.

#### Scenario: AdoptTransport replaces HTTP without a new Client
- **WHEN** a later `New` reuses a live Client and calls `AdoptTransport` with a different TLS or HTTP timeout
- **THEN** later LAPI requests use the new HTTP client
- **AND** the previous HTTP client’s idle connections are closed
- **AND** an INFO line names the replaced transport fields

#### Scenario: Concurrent transport replace last-writes
- **WHEN** two constructors call transport replace on the same Client
- **THEN** the Client’s subsequent LAPI HTTP uses one of those transports
- **AND** the replaced HTTP client’s idle connections are closed
