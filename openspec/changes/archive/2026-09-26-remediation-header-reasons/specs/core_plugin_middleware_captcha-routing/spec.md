## MODIFIED Requirements

### Requirement: Solved-form redirect does not remint or re-verify
The Check-true form-POST redirect SHALL set the configured remediation header to `captcha:solved` when that header name is configured. `captcha:solved` SHALL NOT take a third field. It MUST NOT remint the gate cookie. It MUST NOT call the captcha provider. First-solve cookie mint and 302 stay on the captcha challenge handler.

#### Scenario: Check-true form POST keeps the existing cookie
- **WHEN** a captcha-form POST is redirected because `Check` is true
- **THEN** the response is `302 Found`
- **AND** no new gate cookie is issued
- **AND** the provider siteverify endpoint is not called

#### Scenario: Check-true form POST header is captcha:solved
- **WHEN** a captcha-form POST is redirected because `Check` is true
- **AND** the remediation header name is configured
- **THEN** that header value is `captcha:solved`
