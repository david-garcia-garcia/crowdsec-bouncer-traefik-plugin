## Purpose

Governs how this plugin copies an inbound request to the CRS sidecar and classifies the sidecar HTTP status into allow, copied block, or WAF failure.

## Requirements

### Requirement: Copy then classify sidecar status
The plugin SHALL send a copy of the inbound request to `modsecUrl`. The sidecar is inspect-only. Sidecar HTTP 2xx SHALL allow (the bouncer continues). Sidecar HTTP 3xx or 4xx SHALL copy that status and body to the client and MUST NOT call `next`. Sidecar HTTP 5xx SHALL be a WAF failure, not a copied block: the sidecar 5xx body MUST NOT be forwarded. The HTTP client SHALL set `CheckRedirect` so a sidecar 3xx is classified as a block instead of followed.

#### Scenario: Clean GET is allowed
- **WHEN** the sidecar returns HTTP 200
- **THEN** the bouncer continues toward `next`
- **AND** the sidecar body is not copied to the client

#### Scenario: CRS block is copied
- **WHEN** the sidecar returns HTTP 403 with a block page
- **THEN** the client receives that status and body
- **AND** `next` is not called

#### Scenario: Sidecar 5xx is not a copied block
- **WHEN** the sidecar returns HTTP 503 with a marker body
- **THEN** that marker body is not forwarded
- **AND** the request follows `bouncerModsecFailureAction`

#### Scenario: Sidecar 3xx is a block
- **WHEN** the sidecar returns HTTP 302
- **THEN** the client receives HTTP 302
- **AND** the plugin does not follow the redirect

### Requirement: Sidecar unavailability is logged once per window
When the sidecar is unreachable or answers 5xx, `Inspect` SHALL log ERROR `crowdsec modsec sidecar unavailable` (`modsecurity.MsgUnavailable`) through `logger.Debounced` with a 5 second window keyed by the message text (process-wide), with attr `host` (the sidecar host, without query or userinfo) and `reason` (`unreachable` or `status`, plus `statusCode` for a status). For `unreachable` it SHALL add attr `error` with the transport error without the request URL, so the visitor's path and query stay off the log. An inbound cancel MUST NOT log this line. A Gate `Admit` error SHALL log ERROR `fail to admit ModSec request` with attr `error`.

#### Scenario: An outage logs one line per window
- **WHEN** the sidecar answers 503 to several requests within 5 seconds
- **THEN** one `crowdsec modsec sidecar unavailable` line is logged

#### Scenario: An unreachable sidecar log says why without the visitor URL
- **WHEN** the sidecar refuses the connection for a request to `/visitor-path?token=visitor-secret`
- **THEN** the `crowdsec modsec sidecar unavailable` line has attr `error` with the dial error
- **AND** it contains neither `visitor-path` nor `visitor-secret`

### Requirement: Inspect copy reuses inbound identity owners
The inspect copy SHALL set sidecar request `Host` to inbound `req.Host`. It SHALL copy Traefik's headers as Traefik left them, minus the shared hop-by-hop list and `Content-Length` (`core_plugin_wafhop_shared-request`). It MUST NOT set `X-Real-IP`. It MUST NOT append `RemoteAddr` to `X-Forwarded-For`. Plugin remediations and logs SHALL keep using `pkg/ip.GetRemoteIP` then `clientrequest.New`. Sidecar `REMOTE_ADDR` SHALL stay the Traefik-to-sidecar hop unless the CRS image is configured with `REMOTEIP_*` / `REAL_IP_*` (not this plugin).

#### Scenario: Host is inbound Host
- **WHEN** the inbound request Host is `example.com:443`
- **THEN** the sidecar request Host is `example.com:443`

#### Scenario: Plugin does not write X-Real-IP
- **WHEN** Traefik did not set `X-Real-IP`
- **THEN** the sidecar request has no `X-Real-IP` added by this plugin

### Requirement: Copied block omits hop-by-hop response headers
`modsecurity.WriteBlock` SHALL copy the sidecar end-to-end headers except `Server`, omitting the shared hop-by-hop list (`wafhop.IsHopByHopHeader`), then the status and body. A header the bouncer already set keeps its value unless the sidecar sends the same name.

#### Scenario: Connection is not copied from the block
- **WHEN** the sidecar 403 includes `Connection: close`
- **THEN** the client response does not include that `Connection` value from the sidecar

#### Scenario: Remediation header survives the copy
- **WHEN** the bouncer set `ban:modsec` before `WriteBlock`
- **AND** the sidecar 403 carries `X-Block`
- **THEN** the client response carries both

### Requirement: Failure action applies when the sidecar gives no verdict
Per-router `bouncerModsecFailureAction` SHALL be `passthrough` (default, call `next`), `ban`, or `captcha`, validated like `bouncerLapiFailureAction` and `bouncerAppsecFailureAction` (`captcha` needs a captcha instance name). Empty SHALL be `passthrough` (`configuration.EffectiveModsecFailureAction`). It SHALL apply to `ErrUnavailable` and to a missing subscribed ModSec client. `ban` SHALL write the operator ban template with `bouncerRemediationStatusCode`, RemediationReason `MODSEC`, header `ban:modsec-failure`, and usage-metrics origin `plugin:modsec_failure`. `captcha` SHALL serve this router's captcha gate with header `captcha:modsec-failure` and the same origin. It MUST NOT apply to a copied 3xx/4xx, HTTP 413, a gate skip, a client-body error, or an expired body read deadline (`core_plugin_middleware_bouncer`). An inbound cancel before or during the sidecar hop SHALL be `wafhop.ErrClientDisconnected`: nothing written by ModSec, no gate Record, no failure action, no `next` (`core_plugin_wafhop_shared-request`).

#### Scenario: Default passthrough on sidecar 5xx
- **WHEN** `bouncerModsecFailureAction` is omitted and the sidecar returns HTTP 500
- **THEN** the request proceeds to `next`
- **AND** no remediation header is set

#### Scenario: Ban on sidecar 5xx
- **WHEN** `bouncerModsecFailureAction` is `ban` and the sidecar returns HTTP 500
- **THEN** the response is the ban template with reason `MODSEC` and `ban:modsec-failure`
- **AND** `next` is not called

#### Scenario: Captcha on an unreachable sidecar
- **WHEN** `bouncerModsecFailureAction` is `captcha` and the sidecar is unreachable
- **THEN** the router's captcha page is served with `captcha:modsec-failure`

#### Scenario: Missing client applies the failure action
- **WHEN** the router subscribes to ModSec and no ModSec client is published
- **AND** `bouncerModsecFailureAction` is `ban`
- **THEN** the response is the ban template with `ban:modsec-failure`

#### Scenario: Inbound cancel is client disconnected
- **WHEN** the inbound context is canceled before or during the sidecar hop
- **THEN** ModSec writes nothing and the bouncer answers client disconnected
- **AND** the gate is not Recorded
- **AND** `next` is not called

#### Scenario: Passthrough does not let a stalled body through
- **WHEN** `bouncerModsecFailureAction` is `passthrough`
- **AND** a body without Content-Length does not arrive within `modsecBodyReadTimeoutSeconds`
- **THEN** the response is HTTP 400 with `error:body-read-timeout`
- **AND** `next` is not called

### Requirement: Action-rule skip skips inspect
When a matching action rule skipped ModSec, ServeHTTP SHALL NOT buffer the body for ModSec, SHALL NOT consult the Gate, and SHALL NOT call the sidecar.

#### Scenario: bypassModsec skips CRS
- **WHEN** a matching row is `{action: [bypassModsec]}`
- **AND** the query string would otherwise trip CRS
- **THEN** the sidecar is not called
- **AND** the request continues

### Requirement: Inspect returns a verdict or a classified error and never writes the response
`(*modsecurity.Client).Inspect(req, dl)` SHALL take the inbound request and its per-request read-deadline control, SHALL return `(*http.Response, error)`, and MUST NOT write the client response. `nil, nil` SHALL mean allow (sidecar 2xx). A non-nil response SHALL mean block (sidecar 3xx or 4xx); the bouncer SHALL set the remediation header `ban:modsec` (when `bouncerRemediationHeadersCustomName` is set), record one dropped request with origin `modsec` and remediation `ban`, and send it with `modsecurity.WriteBlock`, which closes it. An error SHALL be one of `modsecurity.ErrUnavailable` (no verdict), `modsecurity.ErrGateSkip`, `modsecurity.ErrBodyTooLarge` (the same value as `wafhop.ErrBodyTooLarge`), `wafhop.ErrClientDisconnected`, `wafhop.ErrClientBodyRead`, or `wafhop.ErrBodyReadTimeout`. `ErrUnavailable` SHALL cover a transport error or the sidecar client timeout, sidecar 5xx, a sidecar request that could not be built, and an admission error; it MUST NOT cover anything about the client body. A body on any method SHALL be read and forwarded whether or not it has a `Content-Length`. On `ErrBodyTooLarge` the bouncer SHALL answer HTTP 413 and the sidecar MUST NOT be called.

#### Scenario: Block is returned, not written
- **WHEN** the sidecar returns HTTP 403
- **THEN** `Inspect` returns that response with a nil error
- **AND** nothing is written to the client until the bouncer calls `WriteBlock`

#### Scenario: Streamed POST is inspected whatever the failure action
- **WHEN** a POST arrives over HTTP/2 with no Content-Length and a body that ends
- **AND** `bouncerModsecFailureAction` is `passthrough`, `ban`, or `captcha`
- **THEN** the sidecar receives that body
- **AND** `Inspect` does not return `ErrUnavailable` for it

#### Scenario: Removing Content-Length does not get an attack past CRS
- **WHEN** an HTTP/2 POST without Content-Length carries a body that CRS blocks
- **THEN** `Inspect` returns the sidecar block
- **AND** the request does not reach `next`

#### Scenario: A stalled body is a read timeout
- **WHEN** an HTTP/2 POST without Content-Length sends 2 bytes and then nothing
- **THEN** `Inspect` returns `wafhop.ErrBodyReadTimeout` after `modsecBodyReadTimeoutSeconds`
- **AND** the sidecar is not called

### Requirement: Gate skip answers with the ModSec backoff action
When the Client holds a Gate, `Inspect` SHALL `Admit` after the body is read and checked against the limit, and before the sidecar hop. A denied admission SHALL return `ErrGateSkip` without a Report and without a sidecar call. The body is read before admission whether or not the Gate is backing off, so a body read error or `wafhop.ErrBodyReadTimeout` is returned as such, never as `ErrGateSkip`. A usable inspect (2xx or copied 3xx/4xx) SHALL Report success; a transport error or sidecar 5xx SHALL Report failure.

#### Scenario: After the trip the default skip continues
- **WHEN** `bouncerModsecFailureAction` is `ban` and the sidecar fails 5 times in a row
- **AND** `bouncerModsecBackOffAction` is omitted
- **THEN** those 5 requests answer `ban:modsec-failure`
- **AND** the next request does not call the sidecar and reaches `next` with no remediation header

#### Scenario: Body limit still applies after the trip
- **WHEN** the Gate is skipping
- **AND** a POST body exceeds `modsecBodyLimit`
- **THEN** the response is HTTP 413

### Requirement: ModSec gate skip uses bouncerModsecBackOffAction
On `ErrGateSkip` the router SHALL apply its own `bouncerModsecBackOffAction` and MUST NOT apply `bouncerModsecFailureAction`. `passthrough` (default; empty means `passthrough`) SHALL call `next`. `ban` SHALL write the ban template with RemediationReason `MODSEC` and header `ban:modsec-backoff`. `captcha` SHALL serve this router's captcha gate with `captcha:modsec-backoff`. Both SHALL count under origin `plugin:modsec_failure`.

#### Scenario: Backoff action ban
- **WHEN** the ModSec Gate denies admission and `bouncerModsecBackOffAction` is `ban`
- **THEN** the response is the ban template with reason `MODSEC` and `ban:modsec-backoff`
- **AND** the sidecar is not called
- **AND** `next` is not called

#### Scenario: Backoff action captcha
- **WHEN** the ModSec Gate denies admission, `bouncerModsecBackOffAction` is `captcha`, and the router has a usable captcha client
- **THEN** the router's captcha page is served with `captcha:modsec-backoff`

#### Scenario: Failure action does not decide a skip
- **WHEN** the ModSec Gate denies admission, `bouncerModsecFailureAction` is `ban`, and `bouncerModsecBackOffAction` is `passthrough`
- **THEN** the request reaches `next` with no remediation header
