## Purpose

Governs what this plugin does when AppSec does not return a usable verdict: listener HTTP 500, an unexpected listener status, unreachable AppSec, or an io error reading the AppSec response. A client request body never selects this action.

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

### Requirement: Structured AppSec verdicts are not failure actions
HTTP 200 and HTTP 403 with parseable AppSec JSON `action` values (`allow`, `ban`, `challenge`, AppSec `captcha` HTML, or any other non-empty action) SHALL keep existing bot-detection behavior. `BouncerAppsecFailureAction` MUST NOT rewrite those envelopes. HTTP 200 with an empty body or invalid JSON SHALL allow. HTTP 403 with an empty body or invalid JSON SHALL stay fail-closed ban and MUST NOT use `bouncerAppsecFailureAction`. Any other listener status SHALL use `bouncerAppsecFailureAction` (`core_plugin_appsec_failure-action` One action covers AppSec 500, unexpected status, and unreachable).

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
`crowdsecAppsecFailureBlock`, `crowdsecAppsecUnreachableBlock`, and `crowdsecAppsecUnreadableBodyBlock` SHALL be removed from the plugin config struct. Operators who previously set `crowdsecAppsecFailureBlock` or `crowdsecAppsecUnreachableBlock` to `false` MUST set `bouncerAppsecFailureAction: passthrough`. `crowdsecAppsecUnreadableBodyBlock` SHALL have no replacement: no key SHALL let a body of unknown length reach origin uninspected. A route that must not be inspected SHALL be excluded with a `bouncerActionRules` row whose action is `bypassAppsec` or `bypass`.

#### Scenario: Old bool fields are gone
- **WHEN** plugin config is decoded
- **THEN** those three JSON keys are not fields on `Config` and do not change runtime behavior

#### Scenario: Passthrough is not a replacement for the unreadable-body bool
- **WHEN** `bouncerAppsecFailureAction` is `passthrough`
- **AND** an HTTP/2 POST without `Content-Length` carries a body that ends
- **THEN** AppSec receives that body

### Requirement: Unhealthy skip is not a failure action
When the AppSec admission gate denies Allow, `bouncerAppsecFailureAction` SHALL NOT choose ban, passthrough, or captcha. The skip SHALL NOT call AppSec. The request SHALL continue (then ModSec if subscribed). FailureAction SHALL still apply to an admitted miss (HTTP 500, unreachable, response-body io error) and to an admission error other than inbound cancel (for example a gate closed on reclaim). The client body SHALL be read before admission whether or not the gate is backing off, so a body that does not arrive whole is answered as a client-body outcome, never as a skip. Default FailureAction SHALL remain `ban`.

#### Scenario: After trip, skip is pass even when FailureAction is ban
- **WHEN** the AppSec Gate denies Allow
- **AND** `bouncerAppsecFailureAction` is `ban`
- **THEN** the client is not forbidden for that skip
- **AND** AppSec is not called

#### Scenario: Admitted 500 still bans by default
- **WHEN** the Gate admits the request
- **AND** AppSec returns HTTP 500
- **AND** `bouncerAppsecFailureAction` is omitted
- **THEN** the client is forbidden

#### Scenario: A stalled body while backing off is still blocked
- **WHEN** the AppSec Gate is backing off
- **AND** a POST without `Content-Length` does not arrive within `appsecBodyReadTimeoutSeconds`
- **THEN** the response is HTTP 400 with no ban
- **AND** AppSec is not called

### Requirement: One action covers AppSec 500, unexpected status, and unreachable
`BouncerAppsecFailureAction` SHALL apply to: AppSec HTTP 500; any listener status other than 200, 403, and 500 (including 401 and 502, 503, and 504), whether or not the body is parseable JSON; a transport failure with no HTTP response; and an io error while reading the AppSec response body. It SHALL apply only when AppSec failed to give a usable verdict. A client request body, of known or unknown length, MUST NOT select this action: a POST, PUT, PATCH, or DELETE body without `Content-Length` on any HTTP version SHALL be read and inspected like any other body (`core_plugin_appsec_client`), and a body of unknown length that is not received within `appsecBodyReadTimeoutSeconds` SHALL be blocked whatever this action says (`core_plugin_wafhop_shared-request`, `core_plugin_middleware_bouncer`). `ban` SHALL drop the request. `passthrough` on 500, an unexpected status, unreachable, or AppSec response-body io error SHALL continue as allow (then `next`), except when AppSec is in use for this request and the URL path has prefix `/crowdsec-internal/challenge/`: then the bouncer SHALL write HTTP 404 and MUST NOT call `next` (`core_plugin_appsec_bot-detection`). `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. A listener status other than 200, 403, and 500 SHALL NOT be treated as a structured verdict, even when the body is JSON with a non-empty `action`. HTTP 502, 503, and 504 SHALL use this action the same way any other unexpected status does. They SHALL NOT be logged as `appsecQuery:unreachable`. A transport failure with no HTTP response SHALL stay `appsecQuery:unreachable` at Error, with the transport error as attr `error`, on every failed call (not debounced; the admission gate bounds it), and the returned error SHALL be `appsecQuery:unreachable: <transport error>`. An oversized AppSec response body on HTTP 200 SHALL allow. An oversized body on HTTP 403 SHALL error and MUST NOT use this action. A response-body io error SHALL keep the `appsecQuery:readBody` error string (MUST NOT collapse to `appsecQuery:unreachable`). A classified client disconnect while buffering a request body SHALL NOT use this action (`core_plugin_appsec_client`, `core_plugin_middleware_bouncer`). Any other error during client body buffering SHALL be `ErrClientBodyRead` and SHALL NOT use this action either. HTTP 401 SHALL log WARN `Remediation component is not authenticated.` through `logger.Debounced` with an interval of 5 seconds and SHALL NOT emit the unexpected-status WARN. Each unexpected listener status (not 200, not 401, not 403, not 500) SHALL log WARN `The remediation component returned an unexpected status code` with attr `statusCode`. That WARN SHALL be `logger.Debounced` with an interval of 5 seconds. The key is the message text, so the same text is emitted at most once per that interval even when `statusCode` differs. A response-body io error SHALL log Info `appsecQuery:failure` with attr `error`. HTTP 500 SHALL log Info `appsecQuery:failure` with attr `statusCode` through `logger.Debounced` with an interval of 5 seconds and SHALL NOT emit either WARN. It SHALL apply only when the AppSec hop was admitted (the admission gate allowed the call, or no gate exists). A denied Allow SHALL NOT use this action (`ErrGateSkip`).

#### Scenario: Unreachable passthrough
- **WHEN** AppSec is unreachable and `bouncerAppsecFailureAction` is `passthrough`
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
- **THEN** the request proceeds to `next`

#### Scenario: Unreachable passthrough on a challenge path is 404
- **WHEN** AppSec is unreachable or unpublished and `bouncerAppsecFailureAction` is `passthrough`
- **AND** AppSec is in use for this request
- **AND** the URL path has prefix `/crowdsec-internal/challenge/`
- **THEN** the client status is 404
- **AND** `next` is not called

#### Scenario: Unreachable ban
- **WHEN** AppSec is unreachable and `bouncerAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

#### Scenario: Unreachable logs say why
- **WHEN** two AppSec calls fail with a connection error
- **THEN** two Error `appsecQuery:unreachable` lines are logged
- **AND** each has attr `error` with the connection error

#### Scenario: Reverse-proxy HTTP 502, 503, or 504 passthrough
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and `bouncerAppsecFailureAction` is `passthrough`
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
- **THEN** the request proceeds to `next`
- **AND** the client logs WARN `The remediation component returned an unexpected status code` with that status code

#### Scenario: Reverse-proxy HTTP 502, 503, or 504 ban
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and `bouncerAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

#### Scenario: HTTP/2 body without Content-Length is not a failure action
- **WHEN** an HTTP/2 or HTTP/3 POST, PUT, PATCH, or DELETE carries a body without `Content-Length` that ends before `appsecBodyReadTimeoutSeconds`
- **AND** `bouncerAppsecFailureAction` is `ban`
- **THEN** AppSec receives that body as POST
- **AND** the request is not dropped unless AppSec returns a verdict that drops it

#### Scenario: Passthrough does not skip inspection of a body without Content-Length
- **WHEN** an HTTP/2 or HTTP/3 POST carries a body without `Content-Length` and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** AppSec receives that body as POST, not a headers-only GET

#### Scenario: AppSec response-body read io error passthrough
- **WHEN** reading the AppSec response body fails with an io error and `bouncerAppsecFailureAction` is `passthrough`
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
- **THEN** the request proceeds to `next`

#### Scenario: AppSec response-body read io error ban
- **WHEN** reading the AppSec response body fails with an io error and `bouncerAppsecFailureAction` is `ban`
- **THEN** the client is forbidden and the error string keeps `appsecQuery:readBody`

#### Scenario: Client disconnect is not a failure action
- **WHEN** buffering a POST, PUT, PATCH, or DELETE body for AppSec fails because the client disconnected or canceled
- **THEN** `bouncerAppsecFailureAction` does not choose ban, passthrough, or captcha

#### Scenario: HTTP 401 passthrough allows
- **WHEN** the AppSec listener returns HTTP 401 with no parseable JSON `action` and `bouncerAppsecFailureAction` is `passthrough`
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
- **THEN** Query returns allow and the bouncer calls `next`
- **AND** the client logs WARN `Remediation component is not authenticated.`

#### Scenario: HTTP 401 ban forbids
- **WHEN** the AppSec listener returns HTTP 401 with no parseable JSON `action` and `bouncerAppsecFailureAction` is `ban`
- **THEN** Query forbids with `appsecQuery statusCode:401`

#### Scenario: HTTP 401 captcha serves captcha
- **WHEN** the AppSec listener returns HTTP 401 with no parseable JSON `action` and `bouncerAppsecFailureAction` is `captcha`
- **THEN** Query returns `ErrFailureCaptcha` and the bouncer serves the captcha client

#### Scenario: Unexpected status passthrough allows
- **WHEN** the AppSec listener returns an unexpected status (not 200, not 401, not 403, not 500) and `bouncerAppsecFailureAction` is `passthrough`
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
- **THEN** Query returns allow and the bouncer calls `next`
- **AND** the client logs WARN `The remediation component returned an unexpected status code` with that status code

#### Scenario: Unexpected status warn is debounced
- **WHEN** the AppSec listener returns HTTP 418 and then HTTP 502 within 5 seconds
- **THEN** WARN `The remediation component returned an unexpected status code` is emitted once
- **AND** both requests still use `bouncerAppsecFailureAction`

#### Scenario: Parseable body on an unexpected status is not a verdict
- **WHEN** the AppSec listener returns HTTP 401 with `{"action":"ban"}` and `bouncerAppsecFailureAction` is `passthrough`
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
- **THEN** Query returns allow

#### Scenario: Gate skip is not a failure action
- **WHEN** the AppSec Gate denies Allow
- **THEN** `bouncerAppsecFailureAction` does not choose ban, passthrough, or captcha
