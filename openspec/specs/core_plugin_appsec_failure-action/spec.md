## Purpose

Governs what this plugin does when AppSec does not return a usable verdict: listener HTTP 500, unreachable AppSec, or a request body that cannot be buffered for inspection.

## Requirements

### Requirement: CrowdsecAppsecFailureAction is the public AppSec fallback
Public config `bouncerAppsecFailureAction` SHALL be one of `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`. `captcha` SHALL be rejected at ValidateParams unless this router has a non-empty captcha instance name after owner-fill rules (`captchaEnabled` and empty name fills to the Traefik name). Empty SHALL be treated as `ban` (same as omit). Unknown values SHALL be rejected. This key SHALL be per-router (not on `lapi.Client` identity) so two routes can disagree on AppSec fallback against one LAPI. On `Bouncer` the field SHALL stay `appsecFailureAction`.

#### Scenario: Default is ban
- **WHEN** the operator omits `bouncerAppsecFailureAction` and AppSec returns HTTP 500
- **THEN** the client is forbidden (same as today’s `crowdsecAppsecFailureBlock` default true)

#### Scenario: Two routers may differ
- **WHEN** two middlewares share one `lapi.Client` and set different `bouncerAppsecFailureAction` values
- **THEN** each route applies its own AppSec fallback

#### Scenario: Captcha without instance name is invalid
- **WHEN** `bouncerAppsecFailureAction` is `captcha` and `captchaInstanceName` is empty after owner-fill rules
- **THEN** plugin initialization fails validation

### Requirement: One action covers 500, unreachable, and unreadable body
`BouncerAppsecFailureAction` SHALL apply to: AppSec HTTP 500; any listener status other than 200, 403, and 500 (including 401 and 502, 503, and 504), whether or not the body is parseable JSON; a transport failure with no HTTP response; an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH; and an io error while reading the AppSec response body. `ban` SHALL drop the request. `passthrough` on 500, an unexpected status, unreachable, or AppSec response-body io error SHALL continue as allow (then `next`). `passthrough` on unreadable body SHALL keep today’s headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. A listener status other than 200, 403, and 500 SHALL NOT be treated as a structured verdict, even when the body is JSON with a non-empty `action`. HTTP 502, 503, and 504 SHALL use this action the same way any other unexpected status does. They SHALL NOT be logged as `appsecQuery:unreachable`. A transport failure with no HTTP response SHALL stay `appsecQuery:unreachable` at Error. DELETE SHALL NOT be treated as a method that would have sent a body. An oversized AppSec response body on HTTP 200 SHALL allow. An oversized body on HTTP 403 SHALL error and MUST NOT use this action. A response-body io error SHALL keep the `appsecQuery:readBody` error string (MUST NOT collapse to `appsecQuery:unreachable`). A classified client disconnect while buffering a readable request body SHALL NOT use this action (`core_plugin_appsec_client`, `core_plugin_middleware_bouncer`). Unclassified errors during client body buffering SHALL keep the `appsecQuery:GetBody` path and today's ban wiring. Each unexpected listener status SHALL log WARN `The remediation component returned an unexpected status code` with attr `statusCode`. That WARN SHALL be `logger.Debounced` with an interval of one minute. The key is the message text, so the same text is emitted at most once per that interval even when `statusCode` differs. HTTP 500 SHALL log Info `appsecQuery:failure` through `logger.Debounced` with an interval of 15 seconds and SHALL NOT emit that WARN.

#### Scenario: Unreachable passthrough
- **WHEN** AppSec is unreachable and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next`

#### Scenario: Unreachable ban
- **WHEN** AppSec is unreachable and `bouncerAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

#### Scenario: Reverse-proxy HTTP 502, 503, or 504 passthrough
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next`
- **AND** the client logs WARN `The remediation component returned an unexpected status code` with that status code

#### Scenario: Reverse-proxy HTTP 502, 503, or 504 ban
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and `bouncerAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

#### Scenario: Unreadable body passthrough still queries AppSec
- **WHEN** the request body cannot be buffered, the method is POST, PUT, or PATCH, and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** AppSec is queried with headers only (GET) and the original body is not dropped

#### Scenario: Unreadable body ban
- **WHEN** the request body cannot be buffered, the method is POST, PUT, or PATCH, and `bouncerAppsecFailureAction` is `ban`
- **THEN** the request is dropped without calling origin

#### Scenario: AppSec response-body read io error passthrough
- **WHEN** reading the AppSec response body fails with an io error and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next`

#### Scenario: AppSec response-body read io error ban
- **WHEN** reading the AppSec response body fails with an io error and `bouncerAppsecFailureAction` is `ban`
- **THEN** the client is forbidden and the error string keeps `appsecQuery:readBody`

#### Scenario: Unreadable DELETE is not dropped
- **WHEN** an HTTP/2 or HTTP/3 DELETE body cannot be buffered and `bouncerAppsecFailureAction` is `ban`
- **THEN** AppSec is queried with headers only (GET) and the request is not dropped

#### Scenario: Client disconnect is not a failure action
- **WHEN** buffering a readable POST, PUT, PATCH, or DELETE body for AppSec fails because the client disconnected or canceled
- **THEN** `bouncerAppsecFailureAction` does not choose ban, passthrough, or captcha

#### Scenario: HTTP 401 passthrough allows
- **WHEN** the AppSec listener returns HTTP 401 with no parseable JSON `action` and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** Query returns allow and the bouncer calls `next`

#### Scenario: HTTP 401 ban forbids
- **WHEN** the AppSec listener returns HTTP 401 with no parseable JSON `action` and `bouncerAppsecFailureAction` is `ban`
- **THEN** Query forbids with `appsecQuery statusCode:401`

#### Scenario: HTTP 401 captcha serves captcha
- **WHEN** the AppSec listener returns HTTP 401 with no parseable JSON `action` and `bouncerAppsecFailureAction` is `captcha`
- **THEN** Query returns `ErrFailureCaptcha` and the bouncer serves the captcha client

#### Scenario: Unexpected status passthrough allows
- **WHEN** the AppSec listener returns an unexpected status (not 200, not 403, not 500) and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** Query returns allow and the bouncer calls `next`
- **AND** the client logs WARN `The remediation component returned an unexpected status code` with that status code

#### Scenario: Unexpected status warn is debounced
- **WHEN** the AppSec listener returns HTTP 401 and then HTTP 502 within one minute
- **THEN** WARN `The remediation component returned an unexpected status code` is emitted once
- **AND** both requests still use `bouncerAppsecFailureAction`

#### Scenario: Parseable body on an unexpected status is not a verdict
- **WHEN** the AppSec listener returns HTTP 401 with `{"action":"ban"}` and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** Query returns allow

### Requirement: Structured AppSec verdicts are not failure actions
HTTP 200 and HTTP 403 with parseable AppSec JSON `action` values (`allow`, `ban`, `challenge`, AppSec `captcha` HTML, or any other non-empty action) SHALL keep existing bot-detection behavior. `BouncerAppsecFailureAction` MUST NOT rewrite those envelopes. HTTP 200 with an empty body or invalid JSON SHALL allow. HTTP 403 with an empty body or invalid JSON SHALL stay fail-closed ban and MUST NOT use `bouncerAppsecFailureAction`. Any other listener status SHALL use `bouncerAppsecFailureAction` (`core_plugin_appsec_failure-action` One action covers 500, unreachable, and unreadable body).

#### Scenario: Challenge still relays
- **WHEN** AppSec returns HTTP 403 with `action` `challenge` and a non-empty body
- **THEN** the bouncer relays that envelope regardless of `bouncerAppsecFailureAction`

#### Scenario: Empty 403 still bans
- **WHEN** AppSec returns HTTP 403 with an empty body
- **THEN** Query returns an error and the client is forbidden regardless of `bouncerAppsecFailureAction`

#### Scenario: Unparseable 200 still allows
- **WHEN** AppSec returns HTTP 200 with a body that is not JSON
- **THEN** Query returns allow regardless of `bouncerAppsecFailureAction`

#### Scenario: Unparseable 403 still bans
- **WHEN** AppSec returns HTTP 403 with a body that is not JSON
- **THEN** Query returns an error and the client is forbidden regardless of `bouncerAppsecFailureAction`

### Requirement: Captcha failure action works in appsec mode
`bouncerAppsecFailureAction: captcha` SHALL serve the captcha challenge from the subscribed published captcha client in every `lapiMode`, AppSec-only included. `bouncer.New` MUST NOT construct a local captcha client for that action. `handleRemediationServeHTTP` SHALL ban when the loaded captcha client is empty or not valid. AppSec-only with `captcha` action SHALL subscribe to `captchaInstanceName` the same way any other bouncing router does.

#### Scenario: AppSec failure in AppSec-only with captcha action
- **WHEN** `lapiEnabled` is false, `appsecEnabled` is true, a captcha instance is published, `bouncerAppsecFailureAction` is `captcha`, and the AppSec listener returns HTTP 500
- **THEN** the client receives the captcha challenge
- **AND** the response is not a ban

#### Scenario: AppSec-only with ban action does not require a captcha subscribe
- **WHEN** `lapiEnabled` is false, `appsecEnabled` is true, and `bouncerAppsecFailureAction` is `ban` or omitted
- **THEN** the handler does not subscribe to captcha solely for that action

### Requirement: Three AppSec block booleans are removed
`crowdsecAppsecFailureBlock`, `crowdsecAppsecUnreachableBlock`, and `crowdsecAppsecUnreadableBodyBlock` SHALL be removed from the plugin config struct. Operators who previously set those bools to `false` MUST set `crowdsecAppsecFailureAction: passthrough`.

#### Scenario: Old bool fields are gone
- **WHEN** plugin config is decoded
- **THEN** those three JSON keys are not fields on `Config` and do not change runtime behavior
