## REMOVED Requirements

### Requirement: Inspect classifies and never writes the response
**Reason**: `Inspect` no longer takes the failure action, and `ErrUnavailable` no longer covers a POST, PUT, or PATCH body streamed without a length: that body is read and inspected under `modsecBodyReadTimeoutSeconds`, so a client that leaves out `Content-Length` no longer gets past CRS uninspected under the default `passthrough`. Every other clause moves to "Inspect returns a verdict or a classified error and never writes the response".
**Migration**: Nothing to configure. A route that carries real streaming request bodies is excluded with a `bouncerActionRules` row whose action is `bypassModsec` (or `bypass`).

## ADDED Requirements

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

## MODIFIED Requirements

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
