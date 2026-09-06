## MODIFIED Requirements

### Requirement: AppSec forward path drains responses for reuse
`Client.Query` SHALL drain the AppSec HTTP response body on every path where `Do` returns a non-nil response, including HTTP 502, 503, and 504, before returning a failure-action result.

#### Scenario: 502 reuses connection
- **WHEN** AppSec returns HTTP 502 and `Query` applies failure action
- **THEN** subsequent queries on the same client reuse one TCP connection

### Requirement: Forwarded request body metadata matches bytes sent
When `Query` forwards a POST body to AppSec, it SHALL omit hop-by-hop headers and stale `Content-Length` / `Transfer-Encoding` from the client copy and SHALL set `Content-Length` to the size of the body bytes actually sent (after truncation when limited).

#### Scenario: Truncated POST has matching Content-Length
- **WHEN** the client POST body exceeds `crowdsecAppsecBodyLimit` and the limit is positive
- **THEN** the AppSec request `Content-Length` equals the truncated byte count

### Requirement: Zero body limit means unlimited forward
When `crowdsecAppsecBodyLimit` is explicitly `0`, `Query` SHALL read and forward the full client POST body to AppSec. It MUST NOT silently downgrade to a bodyless GET.

#### Scenario: Limit zero forwards POST
- **WHEN** `crowdsecAppsecBodyLimit` is `0` and the client sends a POST with a body
- **THEN** AppSec receives a POST whose body equals the full client body
