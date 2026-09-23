## MODIFIED Requirements

### Requirement: Structured AppSec JSON is parsed on the AppSec client
`appsec.Client.Query` SHALL read a bounded AppSec response body (1 MiB) and, when the body is JSON with a non-empty `action`, return that structured result together with a nil error. Fields SHALL be `action`, `http_status`, `user_body_content`, `user_cookies`, and `user_headers`. An empty body or JSON without `action` on HTTP 200 SHALL pass (nil error; the result is an allow action). HTTP 500 and unreachable SHALL honor `bouncerAppsecFailureAction` (`passthrough` | `ban` | `captcha`) instead of `FailureBlock` / `UnreachableBlock`. The response body SHALL be drained so the AppSec HTTP client can reuse the connection.

#### Scenario: Allow JSON passes
- **WHEN** AppSec returns HTTP 200 with `{"action":"allow"}`
- **THEN** `Query` returns a nil error and the request proceeds to `next`

#### Scenario: Empty 200 still passes
- **WHEN** AppSec returns HTTP 200 with an empty body
- **THEN** `Query` returns a nil error and the request proceeds to `next`

### Requirement: Challenge is relayed to the client
When the structured `action` is neither empty, `allow`, nor `ban`, the bouncer SHALL write `http_status`, `user_headers`, `user_cookies` (as `Set-Cookie`), and `user_body_content` to the client and MUST NOT call `next`. `http_status` of zero SHALL be treated as 200. `http_status` outside 100–999 SHALL fall back to `bouncerRemediationStatusCode`. Missing `Content-Type` SHALL fall back to `banTemplateContentType` when that is set. The remediation custom header, when configured, SHALL be set to the action. `blockedRequests` SHALL increment. A `challenge` action with empty `user_body_content` SHALL ban instead of writing an empty page.

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

### Requirement: No new plugin option for bot-detection
Bot-detection SHALL work with existing `appsecEnabled` (and the existing AppSec host/key/TLS knobs). The plugin MUST NOT add a dedicated bot-detection config key.

#### Scenario: AppSec enabled is enough
- **WHEN** `appsecEnabled` is true and AppSec returns a challenge
- **THEN** the plugin relays it without a new middleware field
