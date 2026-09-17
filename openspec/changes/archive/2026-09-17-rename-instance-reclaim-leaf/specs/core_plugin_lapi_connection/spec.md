## MODIFIED Requirements

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
