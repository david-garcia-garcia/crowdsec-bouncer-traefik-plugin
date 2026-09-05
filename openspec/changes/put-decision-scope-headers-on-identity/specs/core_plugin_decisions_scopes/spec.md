## ADDED Requirements

### Requirement: Header map lives on the connection
`CrowdsecConnection` SHALL own the normalized `decisionScopeHeaders` map used for stream `scopes=` and ingest. The per-router bouncer MUST NOT store a second copy. Request header lookup SHALL use that connection map (`RequestScopeValues` on the connection’s map). AppSec failure action SHALL remain per-router on the bouncer.

#### Scenario: Bouncer reads the connection map
- **WHEN** a request arrives on a route whose connection has `decisionScopeHeaders.Country` mapped to `CF-IPCountry`
- **THEN** Country matching reads `CF-IPCountry` from the request using the connection’s map
- **AND** the bouncer has no separate stored copy of that map
