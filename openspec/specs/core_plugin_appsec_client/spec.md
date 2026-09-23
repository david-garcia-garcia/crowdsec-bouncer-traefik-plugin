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
When `appsecEnabled` is true, the owning middleware SHALL reclaim an `appsec.Client` with `reclaim.Open` on the process table (30s grace). The reclaim **ownership** key SHALL be derived from the Traefik middleware name plus AppSec scheme, host, path, resolved key, body limit, TLS material, and `AppsecHTTPTimeoutSeconds`. AppSec instance slot names, `bouncerEnabled`, bounce knobs, LAPI fields, and per-router AppSec failure action MUST NOT be in that key. Two `Open` calls with different middleware names and otherwise identical AppSec knobs SHALL produce two Clients. Two `Open` calls with the same middleware name and identical knobs SHALL Wake the same Client on reload. A change to any keyed AppSec knob SHALL Open a new Client; `AdoptTransport` MUST NOT be the path that applies timeout or TLS changes.

#### Scenario: Two middleware names do not share AppSec
- **WHEN** two owners Open AppSec with different Traefik names and identical URL, key, and body limit
- **THEN** two AppSec Client incarnations exist

#### Scenario: Timeout change is a new Client
- **WHEN** a second Open for the same middleware name changes only `appsecHttpTimeoutSeconds`
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Same name same knobs Wake
- **WHEN** the holder context for an AppSec ownership key is cancelled and a `New` with the same name and knobs runs before grace ends
- **THEN** the same AppSec Client incarnation is returned

### Requirement: AppSec HTTP transport is replaceable after Open
`AdoptTransport` MAY still replace HTTP for the **same** Client incarnation when the ownership key unchanged; when ownership key changes, a new Client owns its transport. `Query` SHALL send from the stored transport on the loaded Client.

#### Scenario: Same-incarnation TLS adopt still allowed
- **WHEN** a reload Wake reuses the same AppSec ownership key and calls `AdoptTransport` with updated TLS on that incarnation
- **THEN** later queries use the adopted transport without a second reclaim Open key

### Requirement: Empty AppSec key falls back to LAPI key
`appsec.Prepare` SHALL copy `lapiKey` into `appsecKey` when the AppSec key is empty, and SHALL copy `lapiScheme` into `appsecScheme` when the AppSec scheme is empty. It MUST NOT copy `lapiHttpTimeoutSeconds` into `appsecHttpTimeoutSeconds`. Callers SHALL run `lapi.Prepare` before `appsec.Prepare`.

#### Scenario: Shared bouncer key still works
- **WHEN** the operator sets `lapiKey` and omits `appsecKey` with AppSec enabled
- **THEN** AppSec authenticates with that LAPI key

#### Scenario: AppSec timeout does not copy from LAPI
- **WHEN** `lapiHttpTimeoutSeconds` is 2, `appsecEnabled` is true, and `appsecHttpTimeoutSeconds` is omitted
- **THEN** AppSec timeout stays 10

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
AppSec HTTP construct SHALL set `http.Client.Timeout` and the stored timeout seconds from `config.AppsecHTTPTimeoutSeconds`. It MUST NOT read a shared or inherited timeout. Inside `pkg/appsec` the stored field SHALL be `HTTPTimeoutSeconds` (prefix already dropped). `Query` SHALL use that stored client. `AdoptTransport` SHALL keep last-writing that transport on the same Client only when the ownership key is unchanged. The AppSec ownership key SHALL include `AppsecHTTPTimeoutSeconds`. Implementations MUST NOT call `EffectiveHTTPTimeoutSeconds`.

#### Scenario: AppSec timeout change is a new Client
- **WHEN** a later `New` enables AppSec with the same middleware name, URL, key, and body limit and `AppsecHTTPTimeoutSeconds` 30
- **THEN** the stored transport Timeout is 30 seconds
- **AND** a later Open that changes only that knob is a new Client

#### Scenario: Query hang honors the AppSec timeout
- **WHEN** AppSec is opened through `New` or `Open` with `AppsecHTTPTimeoutSeconds` 1 and `bouncerAppsecFailureAction` passthrough
- **AND** `Query` hits a listener that never accepts
- **THEN** `Query` returns a passthrough allow
- **AND** the call finishes well under 10 seconds

#### Scenario: AppSec timeout knobs change the ownership key
- **WHEN** two AppSec Opens share middleware name, URL, key, and body limit and differ only on `appsecHttpTimeoutSeconds`
- **THEN** the ownership keys differ
- **AND** two Client incarnations exist

### Requirement: Client disconnect while buffering is not an AppSec query
When `Query` copies a readable POST, PUT, PATCH, or DELETE body and `io.ReadAll` fails with `context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF`, `Query` SHALL return `ErrClientDisconnected` and MUST NOT send a request to the AppSec listener. `bouncerAppsecFailureAction` SHALL NOT change that result. Unclassified body-read errors SHALL keep `appsecQuery:GetBody`. Serving the disconnect (TRACE, optional remediation header, no ban, no origin) is owned by `core_plugin_middleware_bouncer`.

#### Scenario: Canceled body does not reach AppSec
- **WHEN** buffering a readable POST body fails with `context.Canceled`
- **THEN** `Query` returns `ErrClientDisconnected`
- **AND** the AppSec listener is not called
- **AND** `bouncerAppsecFailureAction: ban` does not change that

### Requirement: AppSec identity JSON reuses the session marshaler
AppSec reclaim identity JSON SHALL be produced only by the marshaler in `pkg/appsec/session.go`. Implementations MUST NOT reconstruct that payload in `pkg/configuration` or `pkg/bouncer`. That marshaler SHALL keep `scheme` / `host` / `path` / `key` and SHALL rename `tlsCertificateBouncer` / `tlsCertificateBouncerKey` to `tlsClientCertificate` / `tlsClientKey`. Transport fields still spelled `appsecTLSCertificateBouncer` SHALL use `TLSClientCertificate` / `TLSClientKey`. A field-name change SHALL change the hash. A process restart SHALL build a new Client.

#### Scenario: AppSec hash uses session.go only
- **WHEN** two Opens share middleware name and AppSec knobs
- **THEN** both ownership keys come from `pkg/appsec/session.go`
- **AND** no second hash is computed in `configuration` or `bouncer`
