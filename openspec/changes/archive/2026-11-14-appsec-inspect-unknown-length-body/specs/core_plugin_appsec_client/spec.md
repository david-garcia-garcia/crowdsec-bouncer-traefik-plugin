## RENAMED Requirements

- FROM: `### Requirement: Readable body forwards only on body-bearing methods`
- TO: `### Requirement: Client body forwards only on body-bearing methods`

## MODIFIED Requirements

### Requirement: AppSec is reclaimed by listener identity
When `appsecEnabled` is true, the owning middleware SHALL reclaim an `appsec.Client` with `reclaim.Open` on the process table (30s grace). The reclaim **ownership** key SHALL be derived from the Traefik middleware name plus AppSec scheme, host, path, resolved key, effective body limit (after the non-positive default), `appsecBodyReadTimeoutSeconds`, TLS material, and `AppsecHTTPTimeoutSeconds`. AppSec instance slot names, `bouncerEnabled`, bounce knobs, LAPI fields, and per-router AppSec failure action MUST NOT be in that key. Two `Open` calls with different middleware names and otherwise identical AppSec knobs SHALL produce two Clients. Two `Open` calls with the same middleware name and identical knobs SHALL Wake the same Client on reload. A change to any keyed AppSec knob SHALL Open a new Client; `AdoptTransport` MUST NOT be the path that applies timeout or TLS changes.

#### Scenario: Two middleware names do not share AppSec
- **WHEN** two owners Open AppSec with different Traefik names and identical URL, key, and body limit
- **THEN** two AppSec Client incarnations exist

#### Scenario: Timeout change is a new Client
- **WHEN** a second Open for the same middleware name changes only `appsecHttpTimeoutSeconds`
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Body read timeout change is a new Client
- **WHEN** a second Open for the same middleware name changes only `appsecBodyReadTimeoutSeconds`
- **THEN** the ownership keys differ
- **AND** the second Open returns a different Client incarnation than the first

#### Scenario: Same name same knobs Wake
- **WHEN** the holder context for an AppSec ownership key is cancelled and a `New` with the same name and knobs runs before grace ends
- **THEN** the same AppSec Client incarnation is returned

### Requirement: Client body forwards only on body-bearing methods
`Query` SHALL copy a client body to AppSec only when the method is POST, PUT, PATCH, or DELETE. That copy SHALL NOT depend on whether the client declared `Content-Length` or on the HTTP version: a body without `Content-Length` (HTTP/1.1 chunked, HTTP/2 or HTTP/3 without the header) SHALL be read and forwarded like a body with it, under the read deadline owned by `core_plugin_appsec_body-read-timeout`. Any other method, including a GET or HEAD that carries a body, SHALL be forwarded as a bodyless GET and its body MUST NOT be read. The original verb SHALL always travel on `X-Crowdsec-Appsec-Verb`. A body that is `http.NoBody` SHALL be forwarded as a bodyless GET.

#### Scenario: GET with a body is not forwarded as POST
- **WHEN** a GET request carries a readable body
- **THEN** AppSec receives a GET with no body and no `Content-Length`
- **AND** `X-Crowdsec-Appsec-Verb` is `GET`
- **AND** origin can still read the original body in full

#### Scenario: DELETE body is inspected
- **WHEN** a DELETE request carries a body
- **THEN** AppSec receives those bytes as POST
- **AND** an HTTP/2 or HTTP/3 DELETE body without `Content-Length` is forwarded the same way

#### Scenario: Removing Content-Length does not reduce inspection
- **WHEN** two HTTP/2 POST requests carry the same body, one with `Content-Length` and one without
- **THEN** AppSec receives the same bytes for both

### Requirement: Client disconnect while buffering is not an AppSec query
When `Query` copies a POST, PUT, PATCH, or DELETE body and `io.ReadAll` fails with `context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF`, `Query` SHALL return `ErrClientDisconnected` and MUST NOT send a request to the AppSec listener. When the AppSec body read deadline expired during that read (`core_plugin_appsec_body-read-timeout`), the body-read-timeout outcome SHALL take precedence and `Query` MUST NOT return `ErrClientDisconnected`, whatever error the cut read returned. `bouncerAppsecFailureAction` SHALL NOT change either result. Unclassified body-read errors SHALL keep `appsecQuery:GetBody`. Serving the disconnect (TRACE, optional remediation header, no ban, no origin) is owned by `core_plugin_middleware_bouncer`.

#### Scenario: Canceled body does not reach AppSec
- **WHEN** buffering a POST body fails with `context.Canceled`
- **THEN** `Query` returns `ErrClientDisconnected`
- **AND** the AppSec listener is not called
- **AND** `bouncerAppsecFailureAction: ban` does not change that

#### Scenario: Expired body read deadline is not a disconnect
- **WHEN** the AppSec body read deadline expires while a POST body without `Content-Length` is being read
- **AND** the cut read returns an error that `isClientGoneBodyReadErr` would classify as client-gone
- **THEN** `Query` returns the body-read-timeout outcome, not `ErrClientDisconnected`

## REMOVED Requirements

### Requirement: Zero body limit forwards the full body
**Reason**: `appsecBodyLimit` values `<= 0` no longer mean "unlimited"; an unbounded in-memory copy of a client body (now also for bodies of unknown length) is replaced by the 10 MiB default cap.
**Migration**: Operators who set `appsecBodyLimit: 0` get a 10485760-byte cap. To inspect more, set a larger positive value. To skip body inspection on a route, use a `bouncerActionRules` row with `bypassAppsec`.

## ADDED Requirements

### Requirement: Non-positive body limit is the default cap
An `appsecBodyLimit` of `0` or less SHALL be treated as 10485760 bytes, the same value as the omitted default, for the copy cap and for the AppSec reclaim identity. `ValidateParams` MUST NOT reject a negative `appsecBodyLimit`. `Query` SHALL always cap the copied client body at the effective limit; it MUST NOT copy an unbounded body.

#### Scenario: Zero limit caps at 10 MiB
- **WHEN** `appsecBodyLimit` is `0` and a POST body is longer than 10485760 bytes
- **THEN** AppSec receives the first 10485760 bytes as POST
- **AND** origin can still read the original body in full

#### Scenario: Negative limit is accepted and capped
- **WHEN** `appsecBodyLimit` is `-1`
- **THEN** `ValidateParams` returns no error
- **AND** the effective limit is 10485760

#### Scenario: Zero and omitted share one Client
- **WHEN** two Opens for the same middleware name and knobs differ only in `appsecBodyLimit` `0` versus omitted
- **THEN** the ownership keys are equal
