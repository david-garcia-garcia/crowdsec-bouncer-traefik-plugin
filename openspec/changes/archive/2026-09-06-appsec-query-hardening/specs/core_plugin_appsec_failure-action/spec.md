## MODIFIED Requirements

### Requirement: One action covers 500, unreachable, and unreadable body
`CrowdsecAppsecFailureAction` SHALL apply to: AppSec HTTP 500; transport failure or HTTP 502/503/504; an unreadable HTTP/2 or HTTP/3 body on a method that would have sent a body; and failure to read or cap the AppSec response body before parse. `ban` SHALL drop the request. `passthrough` on 500 or unreachable SHALL continue as allow (then `next`). `passthrough` on unreadable body SHALL keep today’s headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`.

#### Scenario: Response read error passthrough
- **WHEN** reading the AppSec response body fails and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds as allow

#### Scenario: Response read error ban
- **WHEN** reading the AppSec response body fails and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`
