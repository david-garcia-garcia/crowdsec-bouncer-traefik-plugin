## MODIFIED Requirements

### Requirement: One action covers 500, unreachable, and unreadable body
`CrowdsecAppsecFailureAction` SHALL apply to: AppSec HTTP 500; transport failure or HTTP 502/503/504; and an unreadable HTTP/2 or HTTP/3 body on a method that would have sent a body. `ban` SHALL drop the request. `passthrough` on 500 or unreachable SHALL continue as allow (then `next`). `passthrough` on unreadable body SHALL keep today's headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. When `crowdsecMode` is `appsec` and `crowdsecAppsecFailureAction` is `captcha` with a configured captcha provider, `Bouncer.New` SHALL initialize the captcha client so `ErrFailureCaptcha` serves captcha instead of banning.

#### Scenario: Appsec failure captcha serves captcha client
- **WHEN** `crowdsecMode` is `appsec`, `crowdsecAppsecFailureAction` is `captcha`, a captcha provider is configured, and AppSec returns HTTP 500
- **THEN** the bouncer serves the LAPI-style captcha flow (not a ban)
