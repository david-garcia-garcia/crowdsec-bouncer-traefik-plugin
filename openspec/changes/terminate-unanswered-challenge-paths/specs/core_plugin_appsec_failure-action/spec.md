## MODIFIED Requirements

### Requirement: One action covers 500, unreachable, and unreadable body
`BouncerAppsecFailureAction` SHALL apply to: AppSec HTTP 500; transport failure or HTTP 502/503/504; an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH; and an io error while reading the AppSec response body. `ban` SHALL drop the request. `passthrough` on 500, unreachable, or AppSec response-body io error SHALL continue as allow (then `next`), except when AppSec is in use for this request and the URL path has prefix `/crowdsec-internal/challenge/`: then the bouncer SHALL write HTTP 404 and MUST NOT call `next` (`core_plugin_appsec_bot-detection`). `passthrough` on unreadable body SHALL keep today’s headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. HTTP 502, 503, and 504 from the AppSec listener SHALL be unreachable (same fallback as a transport failure), not a generic non-200 ban. DELETE SHALL NOT be treated as a method that would have sent a body. An oversized AppSec response body SHALL NOT use this action: HTTP 200 SHALL allow and non-200 SHALL error as today. A response-body io error SHALL keep the `appsecQuery:readBody` error string (MUST NOT collapse to `appsecQuery:unreachable`). A classified client disconnect while buffering a readable request body SHALL NOT use this action (`core_plugin_appsec_client`, `core_plugin_middleware_bouncer`). Unclassified errors during client body buffering SHALL keep the `appsecQuery:GetBody` path and today's ban wiring.

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
- **THEN** the request proceeds to `next` (same as transport unreachable)

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
