## Purpose

Governs how this plugin copies an inbound request to the CRS sidecar and classifies the sidecar HTTP status into allow, copied block, or WAF failure.

## ADDED Requirements

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
- **AND** the request follows `bouncerModsecFailMode`

#### Scenario: Sidecar 3xx is a block
- **WHEN** the sidecar returns HTTP 302
- **THEN** the client receives HTTP 302
- **AND** the plugin does not follow the redirect

### Requirement: Inspect copy reuses inbound identity owners
The inspect copy SHALL set sidecar request `Host` to inbound `req.Host`. It SHALL copy Traefik's headers as Traefik left them. It MUST NOT set `X-Real-IP`. It MUST NOT append `RemoteAddr` to `X-Forwarded-For`. Plugin remediations and logs SHALL keep using `pkg/ip.GetRemoteIP` then `clientrequest.New`. Sidecar `REMOTE_ADDR` SHALL stay the Traefik-to-sidecar hop unless the CRS image is configured with `REMOTEIP_*` / `REAL_IP_*` (not this plugin).

#### Scenario: Host is inbound Host
- **WHEN** the inbound request Host is `example.com:443`
- **THEN** the sidecar request Host is `example.com:443`

#### Scenario: Plugin does not write X-Real-IP
- **WHEN** Traefik did not set `X-Real-IP`
- **THEN** the sidecar request has no `X-Real-IP` added by this plugin

### Requirement: Copied block omits hop-by-hop response headers
When forwarding a sidecar 3xx/4xx block, the plugin SHALL omit hop-by-hop response headers (`Connection`, `Keep-Alive`, `Transfer-Encoding`, `Upgrade`, `Proxy-*`, `Te`, `Trailer`) and `Server`.

#### Scenario: Connection is not copied from the block
- **WHEN** the sidecar 403 includes `Connection: close`
- **THEN** the client response does not include that `Connection` value from the sidecar

### Requirement: FailMode applies to inspect failure and unhealthy skip
Per-router `bouncerModsecFailMode` SHALL be `open` (default, call `next`) or `close` (empty HTTP 502, do not call `next`). Empty SHALL be `open`. Other values SHALL fail `New`. It SHALL apply to sidecar transport errors, sidecar 5xx, an already-unhealthy gate skip, and a missing subscribed ModSec client. It MUST NOT apply to copied 3xx/4xx. Inbound cancel (`context.Canceled`) SHALL write empty HTTP 502, MUST NOT Report the gate, and MUST NOT use failMode (no `next`).

#### Scenario: Default open on sidecar 5xx
- **WHEN** `bouncerModsecFailMode` is omitted and the sidecar returns HTTP 500
- **THEN** the request proceeds to `next`

#### Scenario: Close on sidecar 5xx
- **WHEN** `bouncerModsecFailMode` is `close` and the sidecar returns HTTP 500
- **THEN** the response is empty HTTP 502
- **AND** `next` is not called

#### Scenario: Inbound cancel is empty 502
- **WHEN** the inbound context is canceled before or during the sidecar hop
- **THEN** the response is empty HTTP 502
- **AND** the gate is not Reported
- **AND** `next` is not called

### Requirement: Gate skip uses failMode and does not call the sidecar
When the Client holds a Gate, ServeHTTP SHALL `Allow` after deny-verbs-with-body and body-limit checks and before the sidecar hop. A denied Allow SHALL NOT Report, SHALL NOT call the sidecar, and SHALL follow `bouncerModsecFailMode`. A usable inspect (2xx or copied 3xx/4xx) SHALL Report success. Transport error or sidecar 5xx SHALL Report failure. Denied Allow is not a Report.

#### Scenario: After trip, skip is fail-open
- **WHEN** the Gate is open and `bouncerModsecFailMode` is `open`
- **THEN** the sidecar is not called
- **AND** the request proceeds to `next`

#### Scenario: Deny-verbs still 400 after trip
- **WHEN** the Gate is open
- **AND** a GET carries a readable body
- **AND** the default deny-verbs list applies
- **THEN** the response is HTTP 400
- **AND** failMode is not used

### Requirement: Action-rule skip skips inspect
When a matching action rule skipped ModSec, ServeHTTP SHALL NOT buffer the body for ModSec, SHALL NOT apply deny-verbs-with-body, SHALL NOT consult the Gate, and SHALL NOT call the sidecar.

#### Scenario: bypassModsec skips CRS
- **WHEN** a matching row is `{action: [bypassModsec]}`
- **AND** the query string would otherwise trip CRS
- **THEN** the sidecar is not called
- **AND** the request continues
