## MODIFIED Requirements

### Requirement: Structured AppSec JSON is parsed on the connection
`CrowdsecConnection.AppsecQuery` SHALL read a bounded AppSec response body (1 MiB) and, when the body is JSON with a non-empty `action`, return that structured result together with a nil error. Fields SHALL be `action`, `http_status`, `user_body_content`, `user_cookies`, and `user_headers`. An empty body or JSON without `action` on HTTP 200 SHALL pass (nil error; the result is an allow action). HTTP 500 and unreachable SHALL honor `AppsecFailureAction` (`passthrough` | `ban` | `captcha`) instead of `FailureBlock` / `UnreachableBlock`. The response body SHALL be drained so the AppSec HTTP client can reuse the connection.

#### Scenario: Allow JSON passes
- **WHEN** AppSec returns HTTP 200 with `{"action":"allow"}`
- **THEN** `AppsecQuery` returns a nil error and the request proceeds to `next`

#### Scenario: Empty 200 still passes
- **WHEN** AppSec returns HTTP 200 with an empty body
- **THEN** `AppsecQuery` returns a nil error and the request proceeds to `next`
