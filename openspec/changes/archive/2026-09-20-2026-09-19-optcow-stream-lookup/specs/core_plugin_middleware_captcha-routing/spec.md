## MODIFIED Requirements

### Requirement: Captcha routing does not use store grace
Captcha-kind routing SHALL decide past-captcha only with `Check` on the request and the client address already chosen for that request. It MUST NOT read or write store keys for captcha grace, including leftover `{ip}_captcha` entries. It MUST NOT acquire a stream lease.

#### Scenario: Stale grace key does not pass Check-path
- **WHEN** a leftover `{remoteIP}_captcha` key exists
- **AND** no valid gate cookie is present
- **AND** captcha kind applies
- **THEN** `Check` is false
- **AND** the request is not treated as past-captcha
