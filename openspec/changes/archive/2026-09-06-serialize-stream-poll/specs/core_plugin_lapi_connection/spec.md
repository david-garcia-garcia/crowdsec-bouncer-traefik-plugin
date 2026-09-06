## ADDED Requirements

### Requirement: LAPI HTTP calls honor HTTPTimeoutSeconds
`crowdsecQuery` SHALL bound each request with `HTTPTimeoutSeconds` (request context deadline and `http.Client.Timeout`). When the transport returns an error, the method MUST NOT read the response status or body. A timeout SHALL surface as an error so stream failure accounting can increment.

#### Scenario: Hung LAPI is bounded
- **WHEN** LAPI does not write response headers within `HTTPTimeoutSeconds`
- **THEN** `crowdsecQuery` returns an error within that bound (plus a small scheduling slack)
- **AND** it does not panic
