## ADDED Requirements

### Requirement: Real stack covers Range and header-mapped scopes
The Pester suite SHALL include cases that inject CrowdSec `Range` decisions with `cscli decisions add --range` and at least one header-mapped scope (`--scope` / `--value`) against the live LAPI. A dedicated compose middleware SHALL set `decisionScopeHeaders`. Range SHALL be proven in stream mode (cache) and none mode (LAPI `?ip=`). Country matching SHALL use a geoenrich Traefik plugin (traefik-geoblock in enrich mode) that writes the mapped country header from a **public** client IP. The suite MUST NOT inject a client-set country header for that Country case. Client IP identity SHALL remain `X-Forwarded-For`. Nested plugin maps (`decisionScopeHeaders`, geoblock `databaseSources`) SHALL be loaded from a file provider.

#### Scenario: Range ban contains the test IP
- **WHEN** a Range ban covers the test client subnet and the request uses that `X-Forwarded-For`
- **THEN** the real-stack route is forbidden, and an IP outside the Range is allowed

#### Scenario: Header-mapped Country ban via geoenrich
- **WHEN** geoblock enrich writes `X-IPCountry` for a public `X-Forwarded-For`, `decisionScopeHeaders` maps `Country` to that header, and a Country ban exists for the enriched code
- **THEN** the real-stack route is forbidden for that public IP, and a private IP (country skipped) is allowed
