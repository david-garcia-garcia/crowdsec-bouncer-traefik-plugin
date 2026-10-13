## MODIFIED Requirements

### Requirement: One action covers 500, unreachable, and unreadable body
`BouncerAppsecFailureAction` SHALL apply to: AppSec HTTP 500; AppSec HTTP 401; any other unexpected listener status that is not 200, not 403, not 500, and not 502/503/504, when the body has no parseable JSON with a non-empty `action`; transport failure or HTTP 502/503/504; an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH; and an io error while reading the AppSec response body. `ban` SHALL drop the request. `passthrough` on 500, 401, unexpected status, unreachable, or AppSec response-body io error SHALL continue as allow (then `next`). `passthrough` on unreadable body SHALL keep today’s headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. HTTP 502, 503, and 504 from the AppSec listener SHALL be unreachable (same fallback as a transport failure), not a generic non-200 ban. DELETE SHALL NOT be treated as a method that would have sent a body. An oversized AppSec response body SHALL NOT use this action: HTTP 200 SHALL allow and non-200 SHALL error as today. A response-body io error SHALL keep the `appsecQuery:readBody` error string (MUST NOT collapse to `appsecQuery:unreachable`). A classified client disconnect while buffering a readable request body SHALL NOT use this action (`core_plugin_appsec_client`, `core_plugin_middleware_bouncer`). Unclassified errors during client body buffering SHALL keep the `appsecQuery:GetBody` path and today's ban wiring. An unexpected-status or 401 failure SHALL be logged at Error with the listener status code. HTTP 500 logging SHALL stay as today.

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
- **WHEN** the AppSec listener returns an unexpected status (not 200, not 403, not 500, not 502/503/504) with no parseable JSON `action` and `bouncerAppsecFailureAction` is `passthrough`
- **THEN** Query returns allow and the bouncer calls `next`

### Requirement: Structured AppSec verdicts are not failure actions
HTTP 200 and parseable AppSec JSON `action` values (`allow`, `ban`, `challenge`, AppSec `captcha` HTML, or any other non-empty action) SHALL keep existing bot-detection behavior. `BouncerAppsecFailureAction` MUST NOT rewrite those envelopes. HTTP 403 with an empty body or invalid JSON SHALL stay fail-closed ban and MUST NOT use `bouncerAppsecFailureAction`. HTTP 401 and other unexpected listener statuses without a parseable non-empty `action` SHALL use `bouncerAppsecFailureAction` (`core_plugin_appsec_failure-action` One action covers 500, unreachable, and unreadable body).

#### Scenario: Challenge still relays
- **WHEN** AppSec returns HTTP 403 with `action` `challenge` and a non-empty body
- **THEN** the bouncer relays that envelope regardless of `bouncerAppsecFailureAction`

#### Scenario: Empty 403 still bans
- **WHEN** AppSec returns HTTP 403 with an empty body
- **THEN** Query returns an error and the client is forbidden regardless of `bouncerAppsecFailureAction`
