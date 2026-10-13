## ADDED Requirements

### Requirement: Challenge HTML sets Cache-Control
When ServeHTTP renders the captcha challenge at HTTP 200, the response SHALL set `Cache-Control` to `no-cache, no-store`. It MUST set that header before `WriteHeader`. The Pass 302 MUST NOT gain this header from this requirement.

#### Scenario: GET challenge includes Cache-Control
- **WHEN** `Validate` returns `None`
- **THEN** the solver receives the captcha challenge at 200
- **AND** `Cache-Control` is `no-cache, no-store`

#### Scenario: Reject challenge includes Cache-Control
- **WHEN** `Validate` returns `Reject`
- **THEN** the solver receives the captcha challenge at 200
- **AND** `Cache-Control` is `no-cache, no-store`

#### Scenario: Pass redirect does not set this header
- **WHEN** `Validate` returns `Pass`
- **THEN** the response status is 302
- **AND** `Cache-Control` is empty
