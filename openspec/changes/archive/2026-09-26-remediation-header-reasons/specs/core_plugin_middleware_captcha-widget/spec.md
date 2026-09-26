## MODIFIED Requirements

### Requirement: ServeHTTP render, retry, and omit-boot
On `Pass`, the challenge handler SHALL mint `crowdsec_captcha_gate`, set the remediation header to `captcha:solved` when configured, and respond `302 Found` to the request URL. `captcha:solved` SHALL NOT take a third field. On `None` or error, it SHALL render the challenge with the boot script and set the remediation header to the caller-supplied challenge-page value when configured. On `Reject` when the widget allows retry, it SHALL render the challenge with the boot script and the same caller-supplied header value. On `Reject` when the widget does not allow retry, it SHALL render the same page with the boot script omitted and the same caller-supplied header value. ServeHTTP MUST NOT hard-code `captcha` or `solved-captcha` as the challenge-page value. ServeHTTP MUST NOT import plugin origins or the closed reason table.

#### Scenario: Pass still mints the gate and redirects
- **WHEN** `Validate` returns `Pass`
- **THEN** the response status is 302
- **AND** the response sets `crowdsec_captcha_gate`

#### Scenario: Pass header is captcha:solved
- **WHEN** `Validate` returns `Pass`
- **AND** the remediation header name is configured
- **THEN** that header value is `captcha:solved`

#### Scenario: Checkbox reject re-renders with boot
- **WHEN** `Validate` returns `Reject`
- **AND** the widget allows retry
- **THEN** the solver receives the captcha challenge at 200
- **AND** the boot script is present

#### Scenario: Score reject omits the boot script
- **WHEN** `Validate` returns `Reject`
- **AND** the widget does not allow retry
- **THEN** the solver receives the captcha challenge at 200
- **AND** the boot script is omitted

#### Scenario: None or error renders with boot
- **WHEN** `Validate` returns `None` or an error
- **THEN** the solver receives the captcha challenge at 200
- **AND** the boot script is present
- **AND** no `crowdsec_captcha_gate` cookie is set
