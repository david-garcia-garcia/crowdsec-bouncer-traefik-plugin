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
After `Query` chooses the bytes sent to AppSec, it SHALL omit the client's `Content-Length` and `Transfer-Encoding` from the copied headers and SHALL set the AppSec request `ContentLength` field and `Content-Length` header from those bytes. It SHALL set that header only on the outbound POST that carries those bytes; a bodyless GET to AppSec SHALL carry no `Content-Length`. `Query` SHALL reuse the `ip` argument already chosen by `pkg/ip.GetRemoteIP`; it MUST NOT reconstruct the client address.

#### Scenario: Forwarded body length wins
- **WHEN** the client `Content-Length` disagrees with the bytes `Query` forwards
- **THEN** the AppSec request `ContentLength` field and `Content-Length` header equal the forwarded length

#### Scenario: Bodyless forward carries no length header
- **WHEN** `Query` forwards a request to AppSec as a bodyless GET
- **THEN** the AppSec request has no `Content-Length` header

### Requirement: Forward path strips hop-by-hop headers
`Query` MUST NOT copy connection-scoped headers onto the AppSec request: `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, `Upgrade` (RFC 7230 section 6.1 with errata 4522). The match SHALL be case-insensitive. `Query` MUST NOT additionally strip header names listed in the client's own `Connection` header: that would let a client hide arbitrary headers (for example `Cookie`) from AppSec. End-to-end headers SHALL still be copied verbatim.

#### Scenario: Hop-by-hop headers never reach the listener
- **WHEN** a client request carries `Connection`, `Keep-Alive`, `Proxy-Authenticate`, `Proxy-Authorization`, `TE`, `Trailer`, `Transfer-Encoding`, or `Upgrade`
- **THEN** none of those headers are present on the AppSec request
- **AND** `Cookie` and `X-Forwarded-For` are still forwarded

### Requirement: Readable body forwards only on body-bearing methods
`Query` SHALL copy a readable client body to AppSec only when the method is POST, PUT, PATCH, or DELETE. Any other method, including a GET or HEAD that carries a body, SHALL be forwarded as a bodyless GET and its body MUST NOT be read. The original verb SHALL always travel on `X-Crowdsec-Appsec-Verb`. This readable-forward set SHALL be a predicate distinct from the unreadable-body drop set (POST, PUT, PATCH): DELETE is in the forward set and MUST NOT enter the drop set. A body that is `http.NoBody` SHALL be forwarded as a bodyless GET.

#### Scenario: GET with a body is not forwarded as POST
- **WHEN** a GET request carries a readable body
- **THEN** AppSec receives a GET with no body and no `Content-Length`
- **AND** `X-Crowdsec-Appsec-Verb` is `GET`
- **AND** origin can still read the original body in full

#### Scenario: DELETE body is inspected
- **WHEN** a DELETE request carries a readable body
- **THEN** AppSec receives those bytes as POST
- **AND** an unreadable DELETE body is still not a drop
