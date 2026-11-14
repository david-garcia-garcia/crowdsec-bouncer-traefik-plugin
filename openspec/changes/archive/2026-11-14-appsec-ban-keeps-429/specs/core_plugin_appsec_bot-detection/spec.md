## MODIFIED Requirements

### Requirement: Structured ban keeps the operator ban template
When the structured `action` is `ban`, the bouncer SHALL use the existing `handleBanServeHTTP` path (operator `banTemplate` / remediation status) and MUST NOT write `user_body_content` as the ban page. The remediation custom header, when configured, SHALL be set to `ban:appsec`. The client status SHALL be 429 when the structured `http_status` is 429 (CrowdSec `RateLimit()`), whatever `bouncerRemediationStatusCode` is. Any other `http_status`, including zero or missing, SHALL use `bouncerRemediationStatusCode`.

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

#### Scenario: Other AppSec ban status uses the remediation status
- **WHEN** AppSec returns `{"action":"ban","http_status":418}`
- **THEN** the client status is `bouncerRemediationStatusCode`
