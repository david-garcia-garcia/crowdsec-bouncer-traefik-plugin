## MODIFIED Requirements

### Requirement: Empty captcha instance name fills only when owned
When `captchaEnabled` is true and the trimmed `captchaInstanceName` is empty, `Prepare` SHALL set the instance name to this middleware's Traefik name. When `captchaEnabled` is false, an empty name SHALL stay empty. The ownership Open key SHALL be the middleware name plus instance-owned captcha knobs (provider, keys, files, timeouts, template, gate, custom paths, and the recaptcha-enterprise knobs: key type, project id, API key, action, min score) plus `logLevel`, `logFilePath`, and `logFormat`. Slot name, `bouncerEnabled`, failure actions, remediation header, and `bouncerStartupBlock` MUST NOT be in that key.

#### Scenario: Owner omit fills to Traefik name
- **WHEN** `captchaEnabled` is true and `captchaInstanceName` is omitted
- **AND** the Traefik middleware name is `cs-owner`
- **THEN** the published captcha alias is `alias:captcha:cs-owner`

#### Scenario: Subscriber omit does not fill
- **WHEN** `captchaEnabled` is false, `bouncerEnabled` is true, and `captchaInstanceName` is omitted
- **THEN** the name stays empty
- **AND** the middleware does not Watch captcha

#### Scenario: Enterprise knob change reclaims
- **WHEN** an owner changes `captchaEnterpriseMinScore` (or another enterprise knob) and `New` runs again
- **THEN** captcha Open uses a different ownership key
- **AND** a new captcha client is created

#### Scenario: Log config change reclaims
- **WHEN** an owner changes `logLevel`, `logFilePath`, or `logFormat` and `New` runs again
- **THEN** captcha Open uses a different ownership key
- **AND** a new captcha client is created
