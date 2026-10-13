## MODIFIED Requirements

### Requirement: Challenge is relayed to the client
When the structured `action` is neither empty, `allow`, nor `ban`, the bouncer SHALL write `http_status`, `user_headers`, `user_cookies` (as `Set-Cookie`), and `user_body_content` to the client and MUST NOT call `next`. `http_status` of zero SHALL be treated as 200. `http_status` outside 100–999 SHALL fall back to `bouncerRemediationStatusCode`. Missing `Content-Type` SHALL fall back to `banTemplateContentType` when that is set. The remediation custom header, when configured, SHALL be set to the action. `blockedRequests` SHALL increment. A `challenge` action with empty `user_body_content` SHALL ban instead of writing an empty page. `user_headers` of the same name SHALL replace any existing header of that name on the writer (MUST NOT append a second value). Hop-by-hop names and `Set-Cookie` in `user_headers` SHALL be skipped. Each `user_cookies` entry SHALL be written as its own `Set-Cookie` header (MUST NOT join entries with commas).

#### Scenario: Challenge HTML and cookie are served
- **WHEN** AppSec returns a parseable `action` `challenge` with `http_status` 200, HTML body, Content-Type, and a `__crowdsec_challenge` cookie
- **THEN** the client receives that status, headers, cookie, and body, and the backend is not called

#### Scenario: Empty challenge body is a ban
- **WHEN** AppSec returns `action` `challenge` and `user_body_content` is empty
- **THEN** the client is forbidden with the operator ban page

#### Scenario: Missing http_status defaults to 200
- **WHEN** a challenge envelope omits `http_status` or sets it to 0
- **THEN** the client status is 200

#### Scenario: Out-of-range status is clamped
- **WHEN** the structured response has `http_status` 42
- **THEN** the client status is `bouncerRemediationStatusCode` and the process does not panic

#### Scenario: AppSec CSP replaces existing CSP
- **WHEN** the response writer already has `Content-Security-Policy` and AppSec returns a challenge with a `Content-Security-Policy` in `user_headers`
- **THEN** the client has exactly one `Content-Security-Policy` equal to the AppSec value

#### Scenario: Each user_cookies value is its own Set-Cookie
- **WHEN** AppSec returns a challenge with two `user_cookies` values
- **THEN** the client has two `Set-Cookie` headers, one per value
