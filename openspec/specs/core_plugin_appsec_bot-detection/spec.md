## Purpose

Relay CrowdSec 1.8 AppSec structured remediations (bot-detection challenge HTML, cookies, and callback) through this Traefik plugin instead of treating every non-200 AppSec status as a silent ban.

## Requirements

### Requirement: Client IP for AppSec is GetRemoteIP
The bouncer SHALL pass the address from `pkg/ip.GetRemoteIP` into `appsec.Client.Query` as today (`X-Crowdsec-Appsec-Ip`). AppSec MUST NOT parse `RemoteAddr` or cookies to invent a second client address.

#### Scenario: Forwarded IP is the AppSec client
- **WHEN** Traefik forwards a trusted `X-Forwarded-For` and AppSec is enabled
- **THEN** the AppSec request includes that address in `X-Crowdsec-Appsec-Ip`

### Requirement: Structured AppSec JSON is parsed on the AppSec client
`appsec.Client.Query` SHALL read a bounded AppSec response body (1 MiB) on HTTP 200 and HTTP 403 and, when that body is JSON with a non-empty `action`, return that structured result together with a nil error. Fields SHALL be `action`, `http_status`, `user_body_content`, `user_cookies`, and `user_headers`. An empty body, invalid JSON, or JSON without `action` on HTTP 200 SHALL pass (nil error; the result is an allow action). HTTP 500 and every other listener status SHALL honor `bouncerAppsecFailureAction` (`passthrough` | `ban` | `captcha`) instead of `FailureBlock` / `UnreachableBlock`, including when the body is JSON with a non-empty `action`. A transport failure with no HTTP response SHALL honor that action too. HTTP 403 with an empty body or invalid JSON SHALL stay fail-closed ban. The response body SHALL be drained so the AppSec HTTP client can reuse the connection.

#### Scenario: Allow JSON passes
- **WHEN** AppSec returns HTTP 200 with `{"action":"allow"}`
- **THEN** `Query` returns a nil error and the request proceeds to `next`

#### Scenario: Empty 200 still passes
- **WHEN** AppSec returns HTTP 200 with an empty body
- **THEN** `Query` returns a nil error and the request proceeds to `next`

#### Scenario: HTTP 401 passthrough allows
- **WHEN** AppSec returns HTTP 401 with no parseable JSON `action` and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** `Query` returns a nil error and the request proceeds to `next`

### Requirement: Challenge is relayed to the client
When the structured `action` is `challenge` with non-empty `user_body_content`, or is not empty, `allow`, `ban`, `captcha`, or `challenge` and has non-empty `user_body_content`, the bouncer SHALL write `http_status`, `user_headers`, `user_cookies` (as `Set-Cookie`), and `user_body_content` to the client and MUST NOT call `next`. `http_status` of zero SHALL be treated as 200. `http_status` outside 100–999 SHALL fall back to `bouncerRemediationStatusCode`. Missing `Content-Type` SHALL fall back to `banTemplateContentType` when that is set. When `bouncerRemediationHeadersCustomName` is configured, a `challenge` action with non-empty `user_body_content` SHALL set that header to `captcha:challenge`. Any other relayed action SHALL set that header to `{sanitized-action}:appsec`, where sanitized-action is the AppSec action trimmed, with CR/LF/TAB stripped, and `:` replaced by `_` so kind stays one field. `allow`, empty, and `captcha` MUST NOT reach relay. A relay whose request path is under `/crowdsec-internal/challenge/` MUST NOT increment `dropped` (unit `request` or unit `byte`). A relay on any other path SHALL increment `dropped` once (request and bytes). Bans and captcha-gate remediations are not this relay and stay counted as today. A `challenge` action with empty `user_body_content` SHALL ban instead of writing an empty page, and when the header name is configured the value SHALL be `ban:appsec-challenge-empty`. An action other than `allow`, `ban`, `captcha`, or `challenge` with empty `user_body_content` SHALL ban with the operator ban page (template reason `APPSEC`, metrics origin `appsec`) instead of writing an empty page, and when the header name is configured the value SHALL be `ban:appsec-action-empty`. `user_headers` of the same name SHALL replace any existing header of that name on the writer (MUST NOT append a second value). Hop-by-hop names and `Set-Cookie` in `user_headers` SHALL be skipped. Each `user_cookies` entry SHALL be written as its own `Set-Cookie` header (MUST NOT join entries with commas).

#### Scenario: Challenge HTML and cookie are served
- **WHEN** AppSec returns a parseable `action` `challenge` with `http_status` 200, HTML body, Content-Type, and a `__crowdsec_challenge` cookie
- **THEN** the client receives that status, headers, cookie, and body, and the backend is not called

#### Scenario: Challenge header is captcha:challenge
- **WHEN** AppSec returns a parseable `action` `challenge` with non-empty `user_body_content`
- **AND** `bouncerRemediationHeadersCustomName` is `X-Remediation`
- **THEN** the response header `X-Remediation` is `captcha:challenge`

#### Scenario: Empty challenge body is a ban
- **WHEN** AppSec returns `action` `challenge` and `user_body_content` is empty
- **THEN** the client is forbidden with the operator ban page

#### Scenario: Empty challenge body header is ban:appsec-challenge-empty
- **WHEN** AppSec returns `action` `challenge` and `user_body_content` is empty
- **AND** `bouncerRemediationHeadersCustomName` is `X-Remediation`
- **THEN** the response header `X-Remediation` is `ban:appsec-challenge-empty`

#### Scenario: Unknown AppSec action header is action:appsec
- **WHEN** AppSec returns a parseable `action` other than `allow`, `ban`, `captcha`, or `challenge` with non-empty `user_body_content`
- **AND** `bouncerRemediationHeadersCustomName` is `X-Remediation`
- **THEN** the client receives that body
- **AND** the response header `X-Remediation` is that action, sanitized, plus `:appsec`

#### Scenario: Unknown AppSec action without a body is a ban
- **WHEN** AppSec returns `{"action":"tarpit","http_status":403}` with no `user_body_content`
- **AND** `bouncerRemediationHeadersCustomName` is `X-Remediation`
- **THEN** the client receives the operator ban page with `bouncerRemediationStatusCode`
- **AND** the response header `X-Remediation` is `ban:appsec-action-empty`
- **AND** the backend is not called

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

#### Scenario: Challenge page increments dropped once
- **WHEN** AppSec returns a parseable `action` `challenge` with non-empty `user_body_content`
- **AND** the request path is `/protected`
- **THEN** usage-metrics `dropped` / `request` for origin `appsec` increments by 1

#### Scenario: Challenge callback does not increment dropped
- **WHEN** AppSec returns a parseable `action` `challenge` with non-empty `user_body_content`
- **AND** the request path is `/crowdsec-internal/challenge/submit`
- **THEN** usage-metrics `dropped` / `request` for origin `appsec` does not increment

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

### Requirement: Legacy non-JSON AppSec 403 still bans
When AppSec returns a non-200 status and the body is empty or not a structured action, the bouncer SHALL ban as today (`handleBanServeHTTP` with `ReasonAPPSEC`).

#### Scenario: Empty 403 is a ban
- **WHEN** AppSec returns HTTP 403 with an empty body
- **THEN** the client is forbidden with the operator ban page and `next` is not called

### Requirement: No new plugin option for bot-detection
Bot-detection SHALL work with existing `appsecEnabled` (and the existing AppSec host/key/TLS knobs). The plugin MUST NOT add a dedicated bot-detection config key.

#### Scenario: AppSec enabled is enough
- **WHEN** `appsecEnabled` is true and AppSec returns a challenge
- **THEN** the plugin relays it without a new middleware field

### Requirement: AppSec captcha verdict uses the router captcha gate
An AppSec `captcha` verdict SHALL be remediated as captcha kind through the same captcha gate that serves a CrowdSec captcha decision, with metrics origin `appsec`, header reason `appsec`, and downgrade template reason `APPSEC`. The bouncer MUST NOT write the envelope's `http_status`, `user_headers`, `user_cookies`, or `user_body_content`. When a captcha action rule matched the request, the rule's captcha gate SHALL serve it instead.

#### Scenario: Captcha JSON is parsed
- **WHEN** AppSec returns HTTP 403 with `{"action":"captcha","http_status":403}`
- **THEN** `Query` returns a nil error and a result whose `action` is `captcha` and `http_status` is 403

#### Scenario: Unsolved visitor gets the router captcha page
- **WHEN** AppSec returns `{"action":"captcha","http_status":403}`
- **AND** this router has a subscribed, published, Valid captcha client
- **AND** the request has no valid gate cookie
- **THEN** the client receives the router's captcha challenge page
- **AND** the backend is not called
- **AND** the response header `X-Remediation` is `captcha:appsec` when that header name is configured
- **AND** one dropped request is counted with origin `appsec` and remediation `captcha`

#### Scenario: Solved visitor continues to the backend
- **WHEN** AppSec returns `{"action":"captcha","http_status":403}`
- **AND** the request carries a valid gate cookie and no challenge marker
- **THEN** the request reaches the backend

#### Scenario: Router without captcha bans
- **WHEN** AppSec returns `{"action":"captcha","http_status":403}`
- **AND** this router did not subscribe to captcha
- **THEN** the client receives the operator ban page
- **AND** the response header `X-Remediation` is `ban:captcha-downgrade` when that header name is configured

#### Scenario: Captcha action rule serves its own gate
- **WHEN** a captcha action rule named `login` matched the request
- **AND** AppSec returns `{"action":"captcha","http_status":403}`
- **AND** the request has no valid gate cookie
- **THEN** the client receives the captcha challenge page with header `captcha:rules`

### Requirement: Challenge-marker POST let through by AppSec stays on the captcha gate
When the AppSec leg (a verdict, or failure action `passthrough`) did not write a response for a request with no matching captcha action rule and no AppSec skip, a POST carrying challenge marker `crowdsec_captcha_challenge=v1` SHALL go to the router captcha gate (metrics origin `appsec`) instead of `next`, provided this router has a subscribed, published, Valid captcha client. Every other request SHALL reach `next` as before, with its body unchanged.

#### Scenario: Captcha solve allowed by AppSec is validated
- **WHEN** AppSec allows a POST that carries `crowdsec_captcha_challenge=v1` and a valid provider token
- **AND** the request has no valid gate cookie
- **THEN** the response is `302 Found` to the same URL with a new gate cookie
- **AND** the backend is not called

#### Scenario: Leftover challenge form allowed by AppSec is redirected
- **WHEN** AppSec allows a POST that carries `crowdsec_captcha_challenge=v1`
- **AND** the request has a valid gate cookie
- **THEN** the response is `302 Found` to the same URL
- **AND** the backend is not called

#### Scenario: Ordinary POST allowed by AppSec reaches the backend
- **WHEN** AppSec allows a POST that does not carry the challenge marker
- **THEN** the backend receives the POST with its body unchanged

#### Scenario: Router without captcha forwards the marker POST
- **WHEN** AppSec allows a POST that carries `crowdsec_captcha_challenge=v1`
- **AND** this router did not subscribe to captcha
- **THEN** the backend receives the POST
