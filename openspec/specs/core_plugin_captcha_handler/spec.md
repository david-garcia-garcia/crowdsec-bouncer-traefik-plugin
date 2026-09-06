## Purpose

Governs the LAPI captcha remediation client: captcha page render, provider siteverify, grace-period cache after solve, and startup validation when a captcha provider is configured.

## Requirements

### Requirement: Captcha template is required when provider is set
When `CaptchaProvider` is non-empty, plugin initialization SHALL require a non-empty `CaptchaFilePath` and a loadable template file. ValidateParams SHALL fail with a clear error when the path is empty or `GetTemplate` fails. The captcha client constructor SHALL return template load errors and MUST NOT serve with a nil template.

#### Scenario: Provider without template path fails startup
- **WHEN** `CaptchaProvider` is set and `CaptchaFilePath` is empty
- **THEN** ValidateParams fails before the plugin accepts traffic

#### Scenario: Unreadable template fails startup
- **WHEN** `CaptchaProvider` is set and the template file is missing or invalid
- **THEN** ValidateParams or captcha client construction fails with the template error

### Requirement: Siteverify includes client remote IP
When verifying a captcha POST, the plugin SHALL send the bouncer-resolved client IP as `remoteip` in the siteverify POST body together with `secret` and `response`. The IP SHALL be the value already passed into captcha from the bouncer; captcha MUST NOT re-parse request headers for this field.

#### Scenario: Siteverify body contains remoteip
- **WHEN** the client submits a captcha response and the bouncer resolved IP `203.0.113.7`
- **THEN** the siteverify POST body includes `remoteip=203.0.113.7`

### Requirement: Grace cache write gates redirect
After provider verify succeeds, the plugin SHALL write the grace-period cache entry and check the result before issuing HTTP 302. On write failure it SHALL log at Error and re-render the captcha page with HTTP 200; it MUST NOT redirect.

#### Scenario: Successful verify and cache write redirects
- **WHEN** siteverify returns success and the grace cache write succeeds
- **THEN** the client receives HTTP 302 to the same URL

#### Scenario: Successful verify and cache write failure re-shows captcha
- **WHEN** siteverify returns success and the grace cache write fails
- **THEN** the client receives HTTP 200 captcha HTML and an Error is logged
- **AND** no HTTP 302 is sent

### Requirement: Retryable provider failures re-show captcha
Transport errors and JSON decode failures from the captcha provider SHALL be treated like a failed verification for UX: log, serve captcha HTML with HTTP 200. The plugin MUST NOT return bare HTTP 400 for these retryable failures. Provider `success: false` SHALL continue to re-render captcha with HTTP 200 and no error to the client.

#### Scenario: Provider transport error re-shows captcha
- **WHEN** siteverify HTTP request fails
- **THEN** the client receives HTTP 200 captcha HTML

#### Scenario: Provider non-JSON response re-shows captcha
- **WHEN** siteverify returns a non-JSON Content-Type
- **THEN** the client receives HTTP 200 captcha HTML

#### Scenario: Provider JSON parse error re-shows captcha
- **WHEN** siteverify returns JSON that cannot be decoded
- **THEN** the client receives HTTP 200 captcha HTML

#### Scenario: Provider success false re-shows captcha
- **WHEN** siteverify returns JSON with `success: false`
- **THEN** the client receives HTTP 200 captcha HTML
