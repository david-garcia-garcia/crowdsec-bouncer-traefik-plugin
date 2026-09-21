## Purpose

`package appsec` owns the reclaim value for one CrowdSec AppSec listener (`appsec.Client`). It does not own LAPI stream, cache, or usage-metrics POST.

## Requirements

### Requirement: AppSec lives in package appsec
`package appsec` SHALL own the reclaim value for one CrowdSec AppSec listener. The exported type SHALL be `Client`. `Query` SHALL perform the AppSec HTTP round-trip and JSON parse. The package MUST NOT import `pkg/lapi` and MUST NOT own stream, cache, live decisions, or usage-metrics POST.

#### Scenario: Bouncer queries AppSec on appsec.Client
- **WHEN** `pkg/bouncer` compiles against this package
- **THEN** `appsec.Client.Query` resolves
- **AND** the call does not go through `lapi.Client`

### Requirement: AppSec is reclaimed by listener identity
When `appsecEnabled` is true, `New` SHALL reclaim an `appsec.Client` with `reclaim.Open` on the process table (30s grace). The reclaim key SHALL be derived from AppSec scheme, host, path, key, and body limit. AppSec TLS, HTTP timeout, middleware name, `next`, templates, trusted IPs, Enabled, LAPI fields, and per-router AppSec failure action MUST NOT be in that key. The Open call SHALL pass `reclaim.Hooks` for Sleep/Wake/Close. `Close` SHALL release idle AppSec HTTP connections.

#### Scenario: Two routers share one AppSec listener
- **WHEN** two `New` calls enable AppSec with the same AppSec URL, key, and body limit and live constructor contexts
- **THEN** both bouncers use the same `appsec.Client` incarnation

#### Scenario: Different AppSec hosts are isolated
- **WHEN** two `New` calls enable AppSec with different AppSec hosts
- **THEN** two AppSec client incarnations exist

#### Scenario: TLS- or timeout-only reload reuses the Client
- **WHEN** a later `New` enables AppSec with the same URL, key, and body limit but a different AppSec TLS knob or HTTP timeout
- **THEN** both constructors use the same `appsec.Client` incarnation

### Requirement: AppSec HTTP transport is replaceable after Open
`Client` SHALL store AppSec HTTP+auth (HTTP client, API key, timeout, AppSec TLS extras) as `atomic.Value`. After `Open` bind, the constructor SHALL call `AdoptTransport` with that config: Store the new transport and idle-close the previous HTTP client. Remaining write-once Client scalar fields MUST NOT become mutable. The Client field that holds that transport MUST NOT be `atomic.Pointer[T]`. `Query` SHALL send the API key and HTTP round-trip from the stored transport.

#### Scenario: AdoptTransport replaces HTTP without a new Client
- **WHEN** a later `New` reuses a live AppSec Client and calls `AdoptTransport` with a different TLS or HTTP timeout
- **THEN** later AppSec requests use the new HTTP client
- **AND** the previous HTTP client’s idle connections are closed
- **AND** an INFO line names the replaced transport fields

### Requirement: Empty AppSec key falls back to LAPI key
`appsec.Prepare` SHALL copy `lapiKey` into `appsecKey` when AppSec is enabled, the AppSec key is empty, and `appsecInstance` is empty, and SHALL copy `lapiScheme` into `appsecScheme` when the AppSec scheme is empty. Callers SHALL run `lapi.Prepare` before `appsec.Prepare`. A named AppSec subscribe MUST NOT inherit the LAPI key.

#### Scenario: Shared bouncer key still works
- **WHEN** the operator sets `lapiKey` and omits `appsecKey` with AppSec enabled
- **THEN** AppSec authenticates with that LAPI key

### Requirement: AppSec User-Agent includes plugin version
AppSec Query SHALL set the outbound `User-Agent` to `Crowdsec-Bouncer-Traefik-Plugin/` plus the plugin version passed into the AppSec Client. It MUST NOT leave that header empty when a version was passed.

#### Scenario: Query User-Agent matches constructed version
- **WHEN** an AppSec Client constructed with plugin version `v9.9.9-test` queries the AppSec listener
- **THEN** the outbound request `User-Agent` is `Crowdsec-Bouncer-Traefik-Plugin/v9.9.9-test`

### Requirement: Query drains every AppSec response
When `Query` receives a non-nil AppSec HTTP response, it SHALL drain and close that body before every return, including listener HTTP 502, 503, and 504. A transport error with no response SHALL NOT require a drain.

#### Scenario: Reverse-proxy status reuses the connection
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and later requests use the same Client
- **THEN** those later requests reuse the keep-alive connection

### Requirement: Zero body limit forwards the full body
When `appsecBodyLimit` is `0`, `Query` SHALL treat the cap as unlimited: it SHALL copy the full readable client body to AppSec and restore that body for origin. It MUST NOT apply a zero-byte read cap that yields an empty body. A positive limit SHALL still cap the copy. The omitted default SHALL remain 10485760.

#### Scenario: Zero limit forwards a POST body
- **WHEN** `appsecBodyLimit` is `0` and the client request has a readable body
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

### Requirement: AppSec transport Timeout is the effective AppSec seconds
AppSec HTTP construct SHALL set `http.Client.Timeout` and the stored timeout seconds from `config.EffectiveHTTPTimeoutSeconds(config.AppsecHttpTimeoutSeconds)`. It MUST NOT read raw `HTTPTimeoutSeconds` when the AppSec override is non-zero. `Query` SHALL use that stored client. `AdoptTransport` SHALL keep last-writing that transport on the same Client. AppSec `IdentityHex` and `Key` MUST still omit `HTTPTimeoutSeconds` and `AppsecHttpTimeoutSeconds`.

#### Scenario: AppSec override adopts Timeout
- **WHEN** a later `New` enables AppSec with the same URL, key, and body limit and `AppsecHttpTimeoutSeconds` 30
- **THEN** both constructors use the same `appsec.Client` incarnation
- **AND** the stored transport Timeout is 30 seconds

#### Scenario: Query hang honors the AppSec override
- **WHEN** AppSec is opened through `New` or `Open` with `HTTPTimeoutSeconds` 10, `AppsecHttpTimeoutSeconds` 1, and `bouncerAppsecFailureAction` passthrough
- **AND** `Query` hits a listener that never accepts
- **THEN** `Query` returns a passthrough allow
- **AND** the call finishes well under 10 seconds

#### Scenario: AppSec timeout knobs do not change Key
- **WHEN** two AppSec configs share URL, key, and body limit and differ only on `HTTPTimeoutSeconds` or `AppsecHttpTimeoutSeconds`
- **THEN** `Key` and `IdentityHex` are the same

### Requirement: Client disconnect while buffering is not an AppSec query
When `Query` copies a readable POST, PUT, PATCH, or DELETE body and `io.ReadAll` fails with `context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF`, `Query` SHALL return `ErrClientDisconnected` and MUST NOT send a request to the AppSec listener. `bouncerAppsecFailureAction` SHALL NOT change that result. Unclassified body-read errors SHALL keep `appsecQuery:GetBody`. Serving the disconnect (TRACE, optional remediation header, no ban, no origin) is owned by `core_plugin_middleware_bouncer`.

#### Scenario: Canceled body does not reach AppSec
- **WHEN** buffering a readable POST body fails with `context.Canceled`
- **THEN** `Query` returns `ErrClientDisconnected`
- **AND** the AppSec listener is not called
- **AND** `bouncerAppsecFailureAction: ban` does not change that
