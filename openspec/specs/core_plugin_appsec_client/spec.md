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

### Requirement: AppSec URI is the inbound-request absolute URL
`Query` SHALL take the inbound request value instead of a parallel IP string plus a bare `*http.Request`. `Query` SHALL set `X-Crowdsec-Appsec-Uri` to that value's absolute client-facing URL. `Query` MUST NOT set that header from `URL.String()` or `URL.Scheme`. `Query` MUST NOT derive scheme from `X-Forwarded-Proto` or `Request.TLS`. `X-Crowdsec-Appsec-Host` SHALL remain `Request.Host`.

#### Scenario: Absolute URI uses constructor scheme
- **WHEN** the inbound-request scheme is `https`
- **AND** `URL.String()` is path-only
- **THEN** `X-Crowdsec-Appsec-Uri` is an absolute URL whose scheme is `https`

#### Scenario: Host header stays Request.Host
- **WHEN** `Query` forwards a request
- **THEN** `X-Crowdsec-Appsec-Host` equals `Request.Host`

### Requirement: Outbound Content-Length matches forwarded bytes
After `Query` chooses the bytes sent to AppSec, it SHALL omit the client's `Content-Length` and `Transfer-Encoding` from the copied headers and SHALL set the AppSec request `ContentLength` field and `Content-Length` header from those bytes. It SHALL set that header only on the outbound POST that carries those bytes; a bodyless GET to AppSec SHALL carry no `Content-Length`. `Query` SHALL reuse the inbound request value's remoteIP already chosen by `pkg/ip.GetRemoteIP`; it MUST NOT reconstruct the client address.

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

### Requirement: AppSec identity JSON reuses the session marshaler
AppSec reclaim identity JSON SHALL be produced only by the marshaler in `pkg/appsec/session.go`. Implementations MUST NOT reconstruct that payload in `pkg/configuration` or `pkg/bouncer`. That marshaler SHALL keep `scheme` / `host` / `path` / `key` and SHALL rename `tlsCertificateBouncer` / `tlsCertificateBouncerKey` to `tlsClientCertificate` / `tlsClientKey`. Transport fields still spelled `appsecTLSCertificateBouncer` SHALL use `TLSClientCertificate` / `TLSClientKey`. A field-name change SHALL change the hash. A process restart SHALL build a new Client.

#### Scenario: AppSec hash uses session.go only
- **WHEN** two Opens share middleware name and AppSec knobs
- **THEN** both ownership keys come from `pkg/appsec/session.go`
- **AND** no second hash is computed in `configuration` or `bouncer`

### Requirement: Query forwards client HTTP version
`Query` SHALL set `X-Crowdsec-Appsec-Http-Version` on the outbound AppSec request to two ASCII digits, major then minor, from the inbound request `ProtoMajor` and `ProtoMinor`. HTTP/1.0 SHALL be `10`, HTTP/1.1 SHALL be `11`, HTTP/2 SHALL be `20`, HTTP/3 SHALL be `30`. `Query` SHALL omit that header when `ProtoMajor` is 0. `Query` MUST NOT parse `Request.Proto` to invent the digits. `Query` MUST NOT snapshot HTTP version on the inbound-request constructor. Other `X-Crowdsec-Appsec-*` headers SHALL remain unchanged.

#### Scenario: HTTP/1.1 encodes as 11
- **WHEN** `Query` forwards a request whose `ProtoMajor` is 1 and `ProtoMinor` is 1
- **THEN** `X-Crowdsec-Appsec-Http-Version` is `11`

#### Scenario: HTTP/2 encodes as 20
- **WHEN** `Query` forwards a request whose `ProtoMajor` is 2 and `ProtoMinor` is 0
- **THEN** `X-Crowdsec-Appsec-Http-Version` is `20`

#### Scenario: HTTP/3 encodes as 30
- **WHEN** `Query` forwards a request whose `ProtoMajor` is 3 and `ProtoMinor` is 0
- **THEN** `X-Crowdsec-Appsec-Http-Version` is `30`

#### Scenario: ProtoMajor 0 omits the header
- **WHEN** `Query` forwards a request whose `ProtoMajor` is 0
- **THEN** `X-Crowdsec-Appsec-Http-Version` is absent

### Requirement: AppSec Client holds one admission gate
When `appsecUnhealthyBackOffPeriodSecs` is greater than 0, `appsec.Client` SHALL hold one `backendbackoff.Gate` from dest utilities and MUST NOT copy that package into this repository. Default period SHALL be 10. `0` SHALL build no gate. A negative period SHALL fail `New`. The period SHALL be the only knob: the trip rule is fixed in `pkg/admission` (`TripFailures` 5, `FailureRatio` 0.30) and the cooldown stays at the period. `Close` SHALL Close a non-nil Gate.

#### Scenario: Default 10 builds a gate
- **WHEN** the operator omits `appsecUnhealthyBackOffPeriodSecs`
- **THEN** the AppSec Client holds one Gate with base cooldown 10 seconds

#### Scenario: Zero builds no gate
- **WHEN** `appsecUnhealthyBackOffPeriodSecs` is 0
- **THEN** the AppSec Client holds no Gate

#### Scenario: Fifth failure in a row trips the gate
- **WHEN** the gate is on and AppSec fails 5 admitted requests in a row with `bouncerAppsecFailureAction` `ban`
- **THEN** those 5 requests are banned
- **AND** the sixth request does not call AppSec and gets `bouncerAppsecBackOffAction`, not the failure action

#### Scenario: Close closes the gate
- **WHEN** an AppSec Client with a Gate is Closed
- **THEN** that Gate is Closed

### Requirement: AppSec admission comes after the body read
`Query` SHALL read the client body first and then `Allow` before the AppSec hop, so a client body error or disconnect never holds an admitted ticket. An admission error other than inbound cancel SHALL apply FailureAction. A denied `Allow` SHALL NOT call AppSec, SHALL NOT apply `bouncerAppsecFailureAction`, and SHALL return `ErrGateSkip`. The bouncer answers it with the router's `bouncerAppsecBackOffAction` (`core_plugin_appsec_failure-action`).

#### Scenario: Gate skip does not call AppSec
- **WHEN** the AppSec Gate denies Allow
- **AND** `bouncerAppsecFailureAction` is `ban` and `bouncerAppsecBackOffAction` is omitted
- **THEN** AppSec is not called
- **AND** the request is not banned for that skip

#### Scenario: Client disconnect holds no ticket
- **WHEN** the client disconnects while its readable body is buffered
- **THEN** `Allow` is not called for that request

### Requirement: AppSec gate records the listener's health
An admitted transport failure, HTTP 500, any listener status other than 200, 401, 403, and 500, or an AppSec response-body io error SHALL `Report` failure, then apply FailureAction. HTTP 401 SHALL `Report` success (a wrong key is a configuration error, not an outage) and still apply FailureAction. A usable verdict SHALL `Report` success. An inbound cancel MUST NOT Report.

#### Scenario: HTTP 401 does not spend gate budget
- **WHEN** the AppSec listener answers HTTP 401 on every request
- **THEN** the AppSec Gate never trips
- **AND** every request still uses `bouncerAppsecFailureAction`

#### Scenario: HTTP 500 spends gate budget
- **WHEN** the AppSec listener answers HTTP 500 on 5 admitted requests in a row
- **THEN** the AppSec Gate trips

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

### Requirement: AppSec backoff logs once per transition
The AppSec gate SHALL log one WARN `crowdsec appsec backoff started` (with `retryIn`) on the first skipped request after a trip, and one INFO `crowdsec appsec backoff ended` when the probe admitted during the backoff reports success. Skipped requests MUST NOT log one line each. A success from a request admitted before the trip MUST NOT log `backoff ended`. `pkg/admission` owns both lines for the AppSec, ModSec, and LAPI Clients.

#### Scenario: Backoff logs once per transition
- **WHEN** the AppSec gate trips and several later requests are skipped
- **THEN** exactly one `crowdsec appsec backoff started` line is logged
- **AND** after a probe succeeds exactly one `crowdsec appsec backoff ended` line is logged
