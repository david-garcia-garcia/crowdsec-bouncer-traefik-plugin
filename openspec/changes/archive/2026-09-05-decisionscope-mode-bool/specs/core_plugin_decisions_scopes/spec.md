## ADDED Requirements

### Requirement: Matching does not import Traefik config
Cached request lookup SHALL take a caller boolean that says whether to consult Range membership. Callers that already know Crowdsec mode SHALL pass true for stream and alone, and false for live and none. The matching package MUST NOT import the Traefik plugin configuration package.

#### Scenario: True consults Range membership
- **WHEN** the caller passes true and Range membership holds a ban that contains the client IP
- **THEN** the request is remediating from that membership

#### Scenario: False skips Range membership
- **WHEN** the caller passes false and Range membership holds a ban that contains the client IP
- **THEN** Range matching does not remediate from that membership
