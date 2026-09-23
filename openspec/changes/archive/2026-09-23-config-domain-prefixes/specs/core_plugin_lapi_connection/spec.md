## MODIFIED Requirements

### Requirement: LiveLookup TTL is passed by the caller
`LiveLookup` SHALL take `defaultDecisionSeconds` from the caller. `Client` MUST NOT store `defaultDecisionTimeout`. The bouncer SHALL pass the value it copied from `config.LapiDefaultDecisionSeconds`. The parameter name SHALL stay `defaultDecisionSeconds`.

#### Scenario: Bouncer supplies live TTL
- **WHEN** a live-mode request misses cache and LAPI returns no active remediation
- **THEN** the cache write uses the TTL that bouncer passed, not a field on Client

### Requirement: LAPI transport Timeout is the effective LAPI seconds
LAPI HTTP construct SHALL set `http.Client.Timeout` and the stored timeout seconds from `config.LapiHTTPTimeoutSeconds`. It MUST NOT read a shared or inherited timeout. Inside `pkg/lapi` the stored field SHALL be `HTTPTimeoutSeconds` (prefix dropped). `AdoptTransport` MAY last-write TLS or other replaceable transport fields on the same Client when the ownership key is unchanged. A later `New` that changes `LapiHTTPTimeoutSeconds` SHALL Open a new Client because that knob is on the LAPI ownership key (`core_plugin_lapi_reclaim-key`). Implementations MUST NOT call `EffectiveHTTPTimeoutSeconds`.

#### Scenario: LAPI timeout change Opens a new Client
- **WHEN** a live stream Client exists with `LapiHTTPTimeoutSeconds` 10
- **AND** a later `New` for the same middleware name, LAPI URL, and key sets `LapiHTTPTimeoutSeconds` to 30
- **THEN** the second Open returns a different Client incarnation
- **AND** the new transport Timeout is 30 seconds
- **AND** the stored `HTTPTimeoutSeconds` is 30

#### Scenario: Same timeout Wake reuses the Client
- **WHEN** a live stream Client exists with `LapiHTTPTimeoutSeconds` 10
- **AND** a later `New` for the same middleware name and ownership knobs leaves that timeout at 10
- **THEN** both constructors receive the same Client
- **AND** the Client does not replace the HTTP client for a timeout-only no-op
