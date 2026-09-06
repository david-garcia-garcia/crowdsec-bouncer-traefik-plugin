## Purpose

Relay CrowdSec 1.8 AppSec structured remediations (bot-detection challenge HTML, cookies, and callback) through this Traefik plugin instead of treating every non-200 AppSec status as a silent ban.

## Requirements

### Requirement: Client IP for AppSec is GetRemoteIP
The bouncer SHALL pass the address from `pkg/ip.GetRemoteIP` into `appsec.Client.Query` as today (`X-Crowdsec-Appsec-Ip`). AppSec MUST NOT parse `RemoteAddr` or cookies to invent a second client address.

#### Scenario: Forwarded IP is the AppSec client
- **WHEN** Traefik forwards a trusted `X-Forwarded-For` and AppSec is enabled
- **THEN** the AppSec request includes that address in `X-Crowdsec-Appsec-Ip`

### Requirement: Structured AppSec JSON is parsed on the AppSec client
`appsec.Client.Query` SHALL read a bounded AppSec response body (1 MiB) and, when the body is JSON with a non-empty `action`, return that structured result together with a nil error. Fields SHALL be `action`, `http_status`, `user_body_content`, `user_cookies`, and `user_headers`. An empty body or JSON without `action` on HTTP 200 SHALL pass (nil error; the result is an allow action). HTTP 500 and unreachable SHALL honor `CrowdsecAppsecFailureAction` (`passthrough` | `ban` | `captcha`) instead of `FailureBlock` / `UnreachableBlock`. The response body SHALL be drained so the AppSec HTTP client can reuse the connection.

#### Scenario: Allow JSON passes
- **WHEN** AppSec returns HTTP 200 with `{"action":"allow"}`
- **THEN** `Query` returns a nil error and the request proceeds to `next`

#### Scenario: Empty 200 still passes
- **WHEN** AppSec returns HTTP 200 with an empty body
- **THEN** `Query` returns a nil error and the request proceeds to `next`

### Requirement: Challenge is relayed to the client
When the structured `action` is neither empty, `allow`, nor `ban`, the bouncer SHALL write `http_status`, `user_headers`, `user_cookies` (as `Set-Cookie`), and `user_body_content` to the client and MUST NOT call `next`. `http_status` of zero SHALL be treated as 200. `http_status` outside 100–999 SHALL fall back to `remediationStatusCode`. Missing `Content-Type` SHALL fall back to `banTemplateContentType` when that is set. The remediation custom header, when configured, SHALL be set to the action. `blockedRequests` SHALL increment. A `challenge` action with empty `user_body_content` SHALL ban instead of writing an empty page.

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
- **THEN** the client status is `remediationStatusCode` and the process does not panic

### Requirement: Structured ban keeps the operator ban template
When the structured `action` is `ban`, the bouncer SHALL use the existing `handleBanServeHTTP` path (operator `banTemplate` / remediation status) and MUST NOT write `user_body_content` as the ban page.

#### Scenario: AppSec ban uses banTemplate
- **WHEN** AppSec returns `{"action":"ban","http_status":403,"user_body_content":"appsec default page"}` and a ban template is configured
- **THEN** the client body is the ban template, not `appsec default page`

### Requirement: Legacy non-JSON AppSec 403 still bans
When AppSec returns a non-200 status and the body is empty or not a structured action, the bouncer SHALL ban as today (`handleBanServeHTTP` with `ReasonAPPSEC`).

#### Scenario: Empty 403 is a ban
- **WHEN** AppSec returns HTTP 403 with an empty body
- **THEN** the client is forbidden with the operator ban page and `next` is not called

### Requirement: No new plugin option for bot-detection
Bot-detection SHALL work with existing `crowdsecAppsecEnabled` (and the existing AppSec host/key/TLS knobs). The plugin MUST NOT add a dedicated bot-detection config key.

#### Scenario: AppSec enabled is enough
- **WHEN** `crowdsecAppsecEnabled` is true and AppSec returns a challenge
- **THEN** the plugin relays it without a new middleware field
