## MODIFIED Requirements

### Requirement: One action covers 500, unreachable, and unreadable body
`CrowdsecAppsecFailureAction` SHALL apply to: AppSec HTTP 500; transport failure or HTTP 502/503/504; and an unreadable HTTP/2 or HTTP/3 body on POST, PUT, or PATCH. DELETE SHALL NOT be treated as a method that would have sent a body for this drop. `ban` SHALL drop the request for those covered failures. `passthrough` on 500 or unreachable SHALL continue as allow (then `next`). `passthrough` on unreadable body SHALL keep today’s headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`.

#### Scenario: Unreachable passthrough
- **WHEN** AppSec is unreachable and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next`

#### Scenario: Unreachable ban
- **WHEN** AppSec is unreachable and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

#### Scenario: Unreadable body passthrough still queries AppSec
- **WHEN** the request body cannot be buffered, the method is POST, PUT, or PATCH, and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** AppSec is queried with headers only (GET) and the original body is not dropped

#### Scenario: Unreadable body ban
- **WHEN** the request body cannot be buffered, the method is POST, PUT, or PATCH, and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the request is dropped without calling origin

#### Scenario: HTTP/3 DELETE unreadable body is not dropped
- **WHEN** the request method is DELETE, `ProtoMajor` is 3, `ContentLength` is less than 0, the body is a real wrapper, and `crowdsecAppsecFailureAction` is `ban`
- **THEN** AppSec is queried with headers only (GET) and the request is not dropped for `appsecQuery:unreadableBody dropped`
