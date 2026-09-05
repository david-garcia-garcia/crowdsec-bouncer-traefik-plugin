## ADDED Requirements

### Requirement: Real stack covers Range and header-mapped scopes
The Pester suite SHALL include cases that inject CrowdSec `Range` decisions with `cscli decisions add --range` and at least one header-mapped scope (`--scope` / `--value`) against the live LAPI. A dedicated compose middleware SHALL set `decisionScopeHeaders`. Range SHALL be proven in stream mode (cache) and none mode (LAPI `?ip=`). Header-mapped matching SHALL send the mapped header on the request in addition to `X-Forwarded-For`. Client IP identity SHALL remain `X-Forwarded-For`.

#### Scenario: Range ban contains the test IP
- **WHEN** a Range ban covers the test client subnet and the request uses that `X-Forwarded-For`
- **THEN** the real-stack route is forbidden, and an IP outside the Range is allowed

#### Scenario: Header-mapped Country ban
- **WHEN** `decisionScopeHeaders` maps `Country` to a test header, a Country ban exists, and the request sends that header
- **THEN** the real-stack route is forbidden, and a different country header is allowed
