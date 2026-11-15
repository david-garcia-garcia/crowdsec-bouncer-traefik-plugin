## MODIFIED Requirements

### Requirement: Structured ban keeps the operator ban template
When the structured `action` is `ban`, the bouncer SHALL use the existing `handleBanServeHTTP` path (operator `banTemplate` / remediation status) and MUST NOT write `user_body_content` as the ban page. The remediation custom header, when configured, SHALL be set to `ban:appsec`. The client status SHALL be the structured `http_status` when it is from 200 to 599 (CrowdSec default 403, 429 for `RateLimit()`, or the `SetReturnCode()` / `user_blocked_http_code` value), whatever `bouncerRemediationStatusCode` is. A zero, missing, or out-of-range `http_status` SHALL use `bouncerRemediationStatusCode`. A 204 or 304 status SHALL be written without the ban template body.

#### Scenario: AppSec ban uses banTemplate
- **WHEN** AppSec returns `{"action":"ban","http_status":403,"user_body_content":"appsec default page"}` and a ban template is configured
- **THEN** the client body is the ban template, not `appsec default page`

#### Scenario: AppSec ban header is ban:appsec
- **WHEN** AppSec returns `{"action":"ban"}`
- **AND** `bouncerRemediationHeadersCustomName` is `X-Remediation`
- **THEN** the response header `X-Remediation` is `ban:appsec`

#### Scenario: AppSec rate-limit ban keeps 429
- **WHEN** AppSec returns `{"action":"ban","http_status":429}` and a ban template is configured
- **THEN** the client status is 429 and the body is the ban template
- **AND** a configured `bouncerRemediationStatusCode` of 503 does not change the 429

#### Scenario: AppSec ban keeps a custom status
- **WHEN** AppSec returns `{"action":"ban","http_status":418}` and a ban template is configured
- **THEN** the client status is 418 and the body is the ban template
- **AND** a configured `bouncerRemediationStatusCode` does not change the 418

#### Scenario: AppSec default 403 wins over the remediation status
- **WHEN** AppSec returns `{"action":"ban","http_status":403}`
- **AND** `bouncerRemediationStatusCode` is 503
- **THEN** the client status is 403

#### Scenario: Invalid AppSec ban status uses the remediation status
- **WHEN** AppSec returns `{"action":"ban"}`, or `http_status` 99, 199, or 600
- **THEN** the client status is `bouncerRemediationStatusCode`

#### Scenario: AppSec ban with a bodyless status has no ban page
- **WHEN** AppSec returns `{"action":"ban","http_status":204}` and a ban template is configured
- **THEN** the client status is 204 and the body is empty
