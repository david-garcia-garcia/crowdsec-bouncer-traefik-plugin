## MODIFIED Requirements

### Requirement: One action covers 500, unreachable, and unreadable body
`CrowdsecAppsecFailureAction` SHALL apply to: AppSec HTTP 500; transport failure or HTTP 502/503/504; an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH; an io error while reading the AppSec response body; and a client-side disconnect or cancellation while buffering a readable request body for AppSec on POST, PUT, PATCH, or DELETE (for example `context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF` during the copy). `ban` SHALL drop the request. `passthrough` on 500, unreachable, or AppSec response-body io error SHALL continue as allow (then `next`). `passthrough` on unreadable body SHALL keep today’s headers-only GET to AppSec. `passthrough` on client body dropped during buffering SHALL allow without calling AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. HTTP 502, 503, and 504 from the AppSec listener SHALL be unreachable (same fallback as a transport failure), not a generic non-200 ban. DELETE SHALL NOT be treated as a method that would have sent a body for the unreadable-body drop policy. An oversized AppSec response body SHALL NOT use this action: HTTP 200 SHALL allow and non-200 SHALL error as today. A response-body io error SHALL keep the `appsecQuery:readBody` error string (MUST NOT collapse to `appsecQuery:unreachable`). A classified client body dropped error SHALL use an `appsecQuery:clientBodyDropped` message (MUST NOT surface only as `appsecQuery:GetBody`). Unclassified errors during client body buffering SHALL keep the `appsecQuery:GetBody` path and today’s ban wiring.

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

#### Scenario: Client body dropped during buffer passthrough
- **WHEN** buffering a readable POST, PUT, PATCH, or DELETE body for AppSec fails because the client disconnected or canceled (`context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF`) and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next` without calling AppSec

#### Scenario: Client body dropped during buffer ban
- **WHEN** buffering a readable POST, PUT, PATCH, or DELETE body for AppSec fails because the client disconnected or canceled and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC` and the error is classified as client body dropped (not an AppSec verdict ban)
