## RENAMED Requirements

- FROM: `### Requirement: Readable body forwards only on body-bearing methods`
- TO: `### Requirement: Client body forwards only on body-bearing methods`

## MODIFIED Requirements

### Requirement: AppSec is reclaimed by listener identity
When `appsecEnabled` is true, the owning middleware SHALL reclaim an `appsec.Client` with `reclaim.Open` on the process table (30s grace). The reclaim **ownership** key SHALL be derived from the Traefik middleware name plus AppSec scheme, host, path, resolved key, effective body limit (after the non-positive default), `appsecBodyReadTimeoutSeconds`, TLS material, `AppsecHTTPTimeoutSeconds`, and `appsecUnhealthyBackOffPeriodSecs` (the only backoff knob). AppSec instance slot names, `bouncerEnabled`, bounce knobs, LAPI fields, and per-router AppSec failure action MUST NOT be in that key. Two `Open` calls with different middleware names and otherwise identical AppSec knobs SHALL produce two Clients. Two `Open` calls with the same middleware name and identical knobs SHALL Wake the same Client on reload. A change to any keyed AppSec knob SHALL Open a new Client; `AdoptTransport` MUST NOT be the path that applies timeout or TLS changes.

#### Scenario: Two middleware names do not share AppSec
- **WHEN** two owners Open AppSec with different Traefik names and identical URL, key, and body limit
- **THEN** two AppSec Client incarnations exist

#### Scenario: Timeout change is a new Client
- **WHEN** a second Open for the same middleware name changes only `appsecHttpTimeoutSeconds`
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Backoff knob change is a new Client
- **WHEN** a second Open for the same middleware name changes only `appsecUnhealthyBackOffPeriodSecs`
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Body read timeout change is a new Client
- **WHEN** a second Open for the same middleware name changes only `appsecBodyReadTimeoutSeconds`
- **THEN** the ownership keys differ
- **AND** the second Open returns a different Client incarnation than the first

#### Scenario: Same name same knobs Wake
- **WHEN** the holder context for an AppSec ownership key is cancelled and a `New` with the same name and knobs runs before grace ends
- **THEN** the same AppSec Client incarnation is returned

### Requirement: Client body forwards only on body-bearing methods
`Query` SHALL copy a client body to AppSec only when the method is POST, PUT, PATCH, or DELETE. That copy SHALL NOT depend on whether the client declared `Content-Length` or on the HTTP version: a body without `Content-Length` (HTTP/1.1 chunked, HTTP/2 or HTTP/3 without the header) SHALL be read and forwarded like a body with it, under `appsecBodyReadTimeoutSeconds` (`core_plugin_wafhop_shared-request`). Any other method, including a GET or HEAD that carries a body, SHALL be forwarded as a bodyless GET and its body MUST NOT be read. The original verb SHALL always travel on `X-Crowdsec-Appsec-Verb`. A body that is `http.NoBody` SHALL be forwarded as a bodyless GET. The bouncer's failure action SHALL NOT change which bodies are copied.

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

#### Scenario: An empty HTTP/2 POST without Content-Length is queried
- **WHEN** an HTTP/2 POST carries an empty body and no `Content-Length`
- **AND** `bouncerAppsecFailureAction` is `ban`
- **THEN** AppSec is queried
- **AND** an allow verdict lets the request reach `next`

### Requirement: Client disconnect while buffering is not an AppSec query
When `Query` copies a POST, PUT, PATCH, or DELETE body and the read fails, `Query` SHALL return `ErrClientDisconnected` when the inbound request context is already canceled or the error is `context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF`. The canceled context SHALL be checked first: net/http cancels it before the read fails on an HTTP/2 stream reset (an error that does not wrap `context.Canceled`) and on an HTTP/1.1 connection read failure (TCP reset, server read timeout). When `appsecBodyReadTimeoutSeconds` expired during that read, `Query` SHALL return `ErrBodyReadTimeout` instead, whatever the cut read returned, and that check SHALL come first. Any other read error SHALL return `ErrClientBodyRead`, with the read error text in the message. In every case `Query` MUST NOT send a request to the AppSec listener, and `bouncerAppsecFailureAction` SHALL NOT change the result. A client-body read error MUST NOT surface as an AppSec ban. Serving these results is owned by `core_plugin_middleware_bouncer`.

#### Scenario: Canceled body does not reach AppSec
- **WHEN** buffering a readable POST body fails with `context.Canceled`
- **THEN** `Query` returns `ErrClientDisconnected`
- **AND** the AppSec listener is not called
- **AND** `bouncerAppsecFailureAction: ban` does not change that

#### Scenario: HTTP/2 stream reset is a disconnect
- **WHEN** an HTTP/2 client resets the stream (RST_STREAM CANCEL) while its readable body is buffered
- **THEN** `Query` returns `ErrClientDisconnected`, although the read error does not wrap `context.Canceled`

#### Scenario: Slow HTTP/2 upload past the server read timeout
- **WHEN** the server read timeout fires while a readable HTTP/2 body is buffered and the request context is not canceled
- **THEN** `Query` returns `ErrClientBodyRead`
- **AND** the AppSec listener is not called

#### Scenario: Expired body read deadline is not a disconnect
- **WHEN** `appsecBodyReadTimeoutSeconds` expires while a POST body without `Content-Length` is read
- **AND** the cut read returns an error that would otherwise be classified as client-gone
- **THEN** `Query` returns `ErrBodyReadTimeout`, not `ErrClientDisconnected`
- **AND** the AppSec listener is not called for any `bouncerAppsecFailureAction`

## REMOVED Requirements

### Requirement: Zero body limit forwards the full body
**Reason**: `appsecBodyLimit` values `<= 0` no longer mean "unlimited". Bodies of unknown length are now read too, so an unbounded in-memory copy of a client body is replaced by the 10 MiB default cap.
**Migration**: Operators who set `appsecBodyLimit: 0` get a 10485760-byte cap. To inspect more, set a larger positive value. To skip body inspection on a route, use a `bouncerActionRules` row with `bypassAppsec`.

## ADDED Requirements

### Requirement: Non-positive body limit is the default cap
An `appsecBodyLimit` of `0` or less SHALL be treated as 10485760 bytes, the same value as the omitted default, both for the copy cap and for the AppSec reclaim identity. `Query` SHALL always cap the copied client body at that effective limit and MUST NOT copy an unbounded body. A body longer than the limit SHALL still be forwarded to origin whole, with only its first bytes inspected.

#### Scenario: Zero limit caps at 10 MiB
- **WHEN** `appsecBodyLimit` is `0` and a POST body is longer than 10485760 bytes
- **THEN** AppSec receives the first 10485760 bytes as POST
- **AND** origin can still read the original body in full

#### Scenario: Negative limit is capped
- **WHEN** `appsecBodyLimit` is `-1`
- **THEN** the effective limit is 10485760

#### Scenario: Zero and omitted share one Client
- **WHEN** two Opens for the same middleware name and knobs differ only in `appsecBodyLimit` `0` versus omitted
- **THEN** the ownership keys are equal
