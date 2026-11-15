## MODIFIED Requirements

### Requirement: One action covers 500, unreachable, and unreadable body
`BouncerAppsecFailureAction` SHALL apply to: AppSec HTTP 500; any listener status other than 200, 403, and 500 (including 401 and 502, 503, and 504), whether or not the body is parseable JSON; a transport failure with no HTTP response; an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH; and an io error while reading the AppSec response body. `ban` SHALL drop the request. `passthrough` on 500, an unexpected status, unreachable, or AppSec response-body io error SHALL continue as allow (then `next`), except when AppSec is in use for this request and the URL path has prefix `/crowdsec-internal/challenge/`: then the bouncer SHALL write HTTP 404 and MUST NOT call `next` (`core_plugin_appsec_bot-detection`). `passthrough` on unreadable body SHALL keep today’s headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. A listener status other than 200, 403, and 500 SHALL NOT be treated as a structured verdict, even when the body is JSON with a non-empty `action`. HTTP 502, 503, and 504 SHALL use this action the same way any other unexpected status does. They SHALL NOT be logged as `appsecQuery:unreachable`. A transport failure with no HTTP response SHALL stay `appsecQuery:unreachable` at Error. DELETE SHALL NOT be treated as a method that would have sent a body. An oversized AppSec response body on HTTP 200 SHALL allow. An oversized body on HTTP 403 SHALL error and MUST NOT use this action. A response-body io error SHALL keep the `appsecQuery:readBody` error string (MUST NOT collapse to `appsecQuery:unreachable`). A classified client disconnect while buffering a readable request body SHALL NOT use this action (`core_plugin_appsec_client`, `core_plugin_middleware_bouncer`). Unclassified errors during client body buffering SHALL keep the `appsecQuery:GetBody` path and today's ban wiring. HTTP 401 SHALL log WARN `Remediation component is not authenticated.` through `logger.Debounced` with an interval of 5 seconds and SHALL NOT emit the unexpected-status WARN. Each unexpected listener status (not 200, not 401, not 403, not 500) SHALL log WARN `The remediation component returned an unexpected status code` with attr `statusCode`. That WARN SHALL be `logger.Debounced` with an interval of 5 seconds. The key is the message text, so the same text is emitted at most once per that interval even when `statusCode` differs. HTTP 500 SHALL log Info `appsecQuery:failure` through `logger.Debounced` with an interval of 5 seconds and SHALL NOT emit either WARN.

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

#### Scenario: Reverse-proxy HTTP 502, 503, or 504 passthrough
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and `bouncerAppsecFailureAction` is `passthrough`
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
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
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
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
