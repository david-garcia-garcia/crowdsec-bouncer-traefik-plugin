## Purpose

Governs what this plugin does when AppSec does not return a usable verdict: listener HTTP 500, unreachable AppSec, or a request body that cannot be buffered for inspection.

## Requirements

### Requirement: CrowdsecAppsecFailureAction is the public AppSec fallback
Public config `crowdsecAppsecFailureAction` SHALL be one of `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`. `captcha` SHALL be rejected at ValidateParams unless a captcha provider is configured. Empty SHALL be treated as `ban` (same as omit). Unknown values SHALL be rejected. This key SHALL be per-router (not on `lapi.Client` identity) so two routes can disagree on AppSec fallback against one LAPI.

#### Scenario: Default is ban
- **WHEN** the operator omits `crowdsecAppsecFailureAction` and AppSec returns HTTP 500
- **THEN** the client is forbidden (same as today’s `crowdsecAppsecFailureBlock` default true)

#### Scenario: Two routers may differ
- **WHEN** two middlewares share one `lapi.Client` and set different `crowdsecAppsecFailureAction` values
- **THEN** each route applies its own AppSec fallback

### Requirement: One action covers 500, unreachable, and unreadable body
`CrowdsecAppsecFailureAction` SHALL apply to: AppSec HTTP 500; transport failure or HTTP 502/503/504; an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH; and an io error while reading the AppSec response body. `ban` SHALL drop the request. `passthrough` on 500, unreachable, or AppSec response-body io error SHALL continue as allow (then `next`). `passthrough` on unreadable body SHALL keep today’s headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. HTTP 502, 503, and 504 from the AppSec listener SHALL be unreachable (same fallback as a transport failure), not a generic non-200 ban. DELETE SHALL NOT be treated as a method that would have sent a body. An oversized AppSec response body SHALL NOT use this action: HTTP 200 SHALL allow and non-200 SHALL error as today. A response-body io error SHALL keep the `appsecQuery:readBody` error string (MUST NOT collapse to `appsecQuery:unreachable`). A classified client disconnect while buffering a readable request body SHALL NOT use this action (`core_plugin_appsec_client`, `core_plugin_middleware_bouncer`). Unclassified errors during client body buffering SHALL keep the `appsecQuery:GetBody` path and today's ban wiring.

#### Scenario: Unreachable passthrough
- **WHEN** AppSec is unreachable and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next`

#### Scenario: Unreachable ban
- **WHEN** AppSec is unreachable and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

#### Scenario: Reverse-proxy HTTP 502, 503, or 504 passthrough
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next` (same as transport unreachable)

#### Scenario: Reverse-proxy HTTP 502, 503, or 504 ban
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

#### Scenario: Unreadable body passthrough still queries AppSec
- **WHEN** the request body cannot be buffered, the method is POST, PUT, or PATCH, and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** AppSec is queried with headers only (GET) and the original body is not dropped

#### Scenario: Unreadable body ban
- **WHEN** the request body cannot be buffered, the method is POST, PUT, or PATCH, and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the request is dropped without calling origin

#### Scenario: AppSec response-body read io error passthrough
- **WHEN** reading the AppSec response body fails with an io error and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next`

#### Scenario: AppSec response-body read io error ban
- **WHEN** reading the AppSec response body fails with an io error and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden and the error string keeps `appsecQuery:readBody`

#### Scenario: Unreadable DELETE is not dropped
- **WHEN** an HTTP/2 or HTTP/3 DELETE body cannot be buffered and `crowdsecAppsecFailureAction` is `ban`
- **THEN** AppSec is queried with headers only (GET) and the request is not dropped

#### Scenario: Client disconnect is not a failure action
- **WHEN** buffering a readable POST, PUT, PATCH, or DELETE body for AppSec fails because the client disconnected or canceled
- **THEN** `crowdsecAppsecFailureAction` does not choose ban, passthrough, or captcha

### Requirement: Structured AppSec verdicts are not failure actions
HTTP 200 and parseable AppSec JSON `action` values (`allow`, `ban`, `challenge`, AppSec `captcha` HTML) SHALL keep existing bot-detection behavior. `CrowdsecAppsecFailureAction` MUST NOT rewrite those envelopes. Legacy empty/non-JSON non-200 (other than 500/502/503/504) SHALL still ban.

#### Scenario: Challenge still relays
- **WHEN** AppSec returns HTTP 403 with `action` `challenge` and a non-empty body
- **THEN** the bouncer relays that envelope regardless of `crowdsecAppsecFailureAction`

### Requirement: Captcha failure action works in appsec mode
`crowdsecAppsecFailureAction: captcha` SHALL serve the configured captcha challenge in every `crowdsecMode`, `appsec` included. `bouncer.New` MUST NOT return an appsec-mode handler whose captcha client is uninitialised while that action is `captcha`, because `handleRemediationServeHTTP` falls back to a ban when the captcha client is not valid. Initialising the captcha client for appsec mode SHALL be conditional on the effective AppSec failure action, so an appsec-mode router that cannot serve a challenge keeps today's early return.

#### Scenario: AppSec failure in appsec mode with captcha action
- **WHEN** `crowdsecMode` is `appsec`, `crowdsecAppsecEnabled` is true, a captcha provider is configured, `crowdsecAppsecFailureAction` is `captcha`, and the AppSec listener returns HTTP 500
- **THEN** the client receives the captcha challenge
- **AND** the response is not a ban

#### Scenario: Appsec mode with ban action keeps the early return
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecFailureAction` is `ban` or omitted
- **THEN** the handler's captcha client is not initialised

### Requirement: Three AppSec block booleans are removed
`crowdsecAppsecFailureBlock`, `crowdsecAppsecUnreachableBlock`, and `crowdsecAppsecUnreadableBodyBlock` SHALL be removed from the plugin config struct. Operators who previously set those bools to `false` MUST set `crowdsecAppsecFailureAction: passthrough`.

#### Scenario: Old bool fields are gone
- **WHEN** plugin config is decoded
- **THEN** those three JSON keys are not fields on `Config` and do not change runtime behavior
