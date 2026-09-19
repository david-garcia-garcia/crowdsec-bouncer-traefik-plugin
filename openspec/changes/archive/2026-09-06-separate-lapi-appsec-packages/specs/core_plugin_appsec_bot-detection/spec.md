## MODIFIED Requirements

### Requirement: Client IP for AppSec is GetRemoteIP
The bouncer SHALL pass the address from `pkg/ip.GetRemoteIP` into `appsec.Client.Query` as today (`X-Crowdsec-Appsec-Ip`). AppSec MUST NOT parse `RemoteAddr` or cookies to invent a second client address.

#### Scenario: Forwarded IP is the AppSec client
- **WHEN** Traefik forwards a trusted `X-Forwarded-For` and AppSec is enabled
- **THEN** the AppSec request includes that address in `X-Crowdsec-Appsec-Ip`

### Requirement: Structured AppSec JSON is parsed on the AppSec client
`appsec.Client.Query` SHALL read a bounded AppSec response body (1 MiB) and, when the body is JSON with a non-empty `action`, return that structured result together with a nil error. Fields SHALL be `action`, `http_status`, `user_body_content`, `user_cookies`, and `user_headers`. An empty body or JSON without `action` on HTTP 200 SHALL pass (nil error; the result is an allow action). HTTP 500 and unreachable SHALL honor `CrowdsecAppsecFailureAction` (`passthrough` | `ban` | `captcha`) instead of `FailureBlock` / `UnreachableBlock`. The response body SHALL be drained so the AppSec HTTP client can reuse the connection.

#### Scenario: Allow JSON passes
- **WHEN** AppSec returns HTTP 200 with `{"action":"allow"}`
- **THEN** `Query` returns a nil error and the request proceeds to `next`

#### Scenario: Empty 200 still passes
- **WHEN** AppSec returns HTTP 200 with an empty body
- **THEN** `Query` returns a nil error and the request proceeds to `next`
