## ADDED Requirements

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
