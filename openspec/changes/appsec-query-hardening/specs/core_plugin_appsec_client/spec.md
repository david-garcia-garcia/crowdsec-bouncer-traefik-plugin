## ADDED Requirements

### Requirement: Query drains every AppSec response
When `Query` receives a non-nil AppSec HTTP response, it SHALL drain and close that body before every return, including listener HTTP 502, 503, and 504. A transport error with no response SHALL NOT require a drain.

#### Scenario: Reverse-proxy status reuses the connection
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and later requests use the same Client
- **THEN** those later requests reuse the keep-alive connection

### Requirement: Zero body limit forwards the full body
When `crowdsecAppsecBodyLimit` is `0`, `Query` SHALL treat the cap as unlimited: it SHALL copy the full readable client body to AppSec and restore that body for origin. It MUST NOT apply a zero-byte read cap that yields an empty body. A positive limit SHALL still cap the copy. The omitted default SHALL remain 10485760.

#### Scenario: Zero limit forwards a POST body
- **WHEN** `crowdsecAppsecBodyLimit` is `0` and the client request has a readable body
- **THEN** AppSec receives that body as POST
- **AND** origin can still read the original body

### Requirement: Outbound Content-Length matches forwarded bytes
After `Query` chooses the bytes sent to AppSec, it SHALL omit the client's `Content-Length` and `Transfer-Encoding` from the copied headers and SHALL set the AppSec request `ContentLength` field and `Content-Length` header from those bytes. `Query` SHALL reuse the `ip` argument already chosen by `pkg/ip.GetRemoteIP`; it MUST NOT reconstruct the client address.

#### Scenario: Forwarded body length wins
- **WHEN** the client `Content-Length` disagrees with the bytes `Query` forwards
- **THEN** the AppSec request `ContentLength` field and `Content-Length` header equal the forwarded length
