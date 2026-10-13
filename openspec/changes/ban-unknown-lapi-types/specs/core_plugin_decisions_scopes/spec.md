## MODIFIED Requirements

### Requirement: Ban wins across scopes
Decision 	ype an and captcha SHALL keep their current remediations. At LAPI ingest (stream Ip/header, stream Range, live, and none), a type that is neither an nor captcha SHALL store and apply as ban. RemediationValue MUST still return empty for those types. When several matching scopes exist, an SHALL win over captcha.

#### Scenario: Range captcha and Country ban
- **WHEN** the client IP is inside a Range captcha and a mapped Country ban also matches
- **THEN** the request is banned, not captcha

#### Scenario: Unknown LAPI type is ban
- **WHEN** stream, live, or none receives a decision whose type is challenge
- **THEN** that decision remediates as ban
- **AND** RemediationValue for challenge is still empty
