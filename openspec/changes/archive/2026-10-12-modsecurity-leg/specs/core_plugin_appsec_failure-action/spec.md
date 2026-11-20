## ADDED Requirements

### Requirement: Unhealthy skip is not a failure action
When the AppSec admission gate denies Allow, `bouncerAppsecFailureAction` SHALL NOT choose ban, passthrough, or captcha. The skip SHALL NOT call AppSec. The request SHALL continue (then ModSec if subscribed). FailureAction SHALL still apply to an admitted miss (HTTP 500, unreachable, unreadable body, response-body io error). Default FailureAction SHALL remain `ban`.

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

## MODIFIED Requirements

### Requirement: One action covers 500, unreachable, and unreadable body
`BouncerAppsecFailureAction` SHALL apply to: AppSec HTTP 500; transport failure or HTTP 502/503/504; an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH; and an io error while reading the AppSec response body. It SHALL apply only when the AppSec hop was admitted (the admission gate allowed the call, or no gate exists). A denied Allow SHALL NOT use this action. `ban` SHALL drop the request. `passthrough` on 500, unreachable, or AppSec response-body io error SHALL continue as allow (then `next`). `passthrough` on unreadable body SHALL keep today's headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. HTTP 502, 503, and 504 from the AppSec listener SHALL be unreachable (same fallback as a transport failure), not a generic non-200 ban. DELETE SHALL NOT be treated as a method that would have sent a body. An oversized AppSec response body SHALL NOT use this action: HTTP 200 SHALL allow and non-200 SHALL error as today. A response-body io error SHALL keep the `appsecQuery:readBody` error string (MUST NOT collapse to `appsecQuery:unreachable`). A classified client disconnect while buffering a readable request body SHALL NOT use this action (`core_plugin_appsec_client`, `core_plugin_middleware_bouncer`). Unclassified errors during client body buffering SHALL keep the `appsecQuery:GetBody` path and today's ban wiring.

#### Scenario: Unreachable passthrough
- **WHEN** AppSec is unreachable and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next`

#### Scenario: Unreachable ban
- **WHEN** AppSec is unreachable and `bouncerAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

#### Scenario: Reverse-proxy HTTP 502, 503, or 504 passthrough
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and `bouncerAppsecFailureAction` is `passthrough`
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

#### Scenario: Gate skip is not a failure action
- **WHEN** the AppSec Gate denies Allow
- **THEN** `bouncerAppsecFailureAction` does not choose ban, passthrough, or captcha
