## Purpose

Bounds how long the AppSec client waits for a client request body of unknown length before inspecting it, and blocks the request when that body does not arrive in time, so that omitting `Content-Length` can never reduce WAF inspection.

## ADDED Requirements

### Requirement: Body read timeout is a public key
`Config` SHALL expose `AppsecBodyReadTimeoutSeconds` (`appsecBodyReadTimeoutSeconds`, int64). `CreateConfig` and `configuration.New` SHALL default it to 30. `ValidateParams` SHALL reject a value less than 1 with an error that names `AppsecBodyReadTimeoutSeconds` and `cannot be less than 1`. There SHALL be no value that disables the deadline. The key SHALL be part of the AppSec reclaim identity (`core_plugin_appsec_client`).

#### Scenario: Default is thirty seconds
- **WHEN** the operator omits `appsecBodyReadTimeoutSeconds`
- **THEN** `CreateConfig` leaves it at 30
- **AND** `ValidateParams` returns no error

#### Scenario: Zero is invalid
- **WHEN** `appsecBodyReadTimeoutSeconds` is 0
- **THEN** `ValidateParams` returns an error that names `AppsecBodyReadTimeoutSeconds` and `cannot be less than 1`

### Requirement: Unknown-length body is read under a total deadline
When `Query` copies a POST, PUT, PATCH, or DELETE body whose length is unknown (no declared `Content-Length`: HTTP/1.1 chunked, HTTP/2 or HTTP/3 without the header), it SHALL read until end of body or `appsecBodyLimit` bytes, whichever comes first, within `appsecBodyReadTimeoutSeconds` from the start of that read. The deadline SHALL be total, not idle. A body that ends or reaches the limit in time SHALL be forwarded and restored for origin like any other body.

#### Scenario: Empty HTTP/2 body without Content-Length is inspected
- **WHEN** an HTTP/2 POST arrives with no `Content-Length` and a body that ends with zero bytes (restic `POST ?create=true`)
- **AND** `bouncerAppsecFailureAction` is `ban`
- **THEN** AppSec is queried
- **AND** an allow verdict lets the request reach origin

#### Scenario: Body that ends in time is forwarded
- **WHEN** an HTTP/2 POST without `Content-Length` sends its whole body before `appsecBodyReadTimeoutSeconds`
- **THEN** AppSec receives those bytes (capped at `appsecBodyLimit`) as POST
- **AND** origin reads the original body in full

#### Scenario: HTTP/1.1 chunked body is bounded the same way
- **WHEN** an HTTP/1.1 POST with `Transfer-Encoding: chunked` sends its whole body before `appsecBodyReadTimeoutSeconds`
- **THEN** AppSec receives those bytes as POST

#### Scenario: Reaching the limit ends the deadline
- **WHEN** a body without `Content-Length` delivers `appsecBodyLimit` bytes before `appsecBodyReadTimeoutSeconds` and keeps streaming
- **THEN** AppSec receives the first `appsecBodyLimit` bytes
- **AND** the remainder streams to origin uninspected with no plugin deadline

#### Scenario: Declared Content-Length has no plugin deadline
- **WHEN** a POST declares `Content-Length` and its body arrives slower than `appsecBodyReadTimeoutSeconds`
- **THEN** the plugin does not cut the read at `appsecBodyReadTimeoutSeconds`

### Requirement: Deadline expiry blocks regardless of the failure action
When the body read deadline expires before the body ends or reaches `appsecBodyLimit`, `Query` SHALL return the body-read-timeout outcome and MUST NOT call the AppSec listener. `bouncerAppsecFailureAction` MUST NOT change that outcome: `passthrough` MUST NOT let the request through and `captcha` MUST NOT serve a captcha. This outcome SHALL take precedence over the client-disconnect classification of the error the cut read returns.

#### Scenario: Stalled HTTP/2 stream with passthrough is blocked
- **WHEN** an HTTP/2 POST without `Content-Length` keeps its body open past `appsecBodyReadTimeoutSeconds`
- **AND** `bouncerAppsecFailureAction` is `passthrough`
- **THEN** the AppSec listener is not called
- **AND** origin is not called
- **AND** the client receives the ban response

#### Scenario: Stalled HTTP/1.1 chunked body is blocked
- **WHEN** an HTTP/1.1 chunked POST keeps its body open past `appsecBodyReadTimeoutSeconds`
- **THEN** the client receives the ban response without waiting for the client to end its body

#### Scenario: Captcha failure action still bans
- **WHEN** the body read deadline expires and `bouncerAppsecFailureAction` is `captcha`
- **THEN** the client receives the ban response, not a captcha challenge

### Requirement: Body read timeout is served as a ban
The bouncer SHALL serve the body-read-timeout outcome as a ban: `bouncerRemediationStatusCode` and the ban template with `ReasonAPPSEC`, remediation header `ban:appsec-body-timeout` when that header is configured, and a `dropped` item with `origin=plugin:appsec_body_timeout` and `remediation=ban`. It SHALL prevail over a matched captcha action rule and log `warnCaptchaSuperseded` like any AppSec ban. Only `bypass` or `bypassAppsec` SHALL avoid it.

#### Scenario: Ban response, header, and origin
- **WHEN** the body read deadline expires and `bouncerRemediationHeadersCustomName` is `X-Remediation`
- **THEN** the response status is `bouncerRemediationStatusCode`
- **AND** `X-Remediation` is `ban:appsec-body-timeout`
- **AND** the `dropped` item has `origin=plugin:appsec_body_timeout`

#### Scenario: bypassAppsec route is not read
- **WHEN** a `bouncerActionRules` row with `bypassAppsec` matches a request with a streaming body without `Content-Length`
- **THEN** the AppSec body is not read and no deadline applies
- **AND** the request reaches origin while the body is still streaming

### Requirement: Body read timeout is logged at WARN
Each body-read-timeout block SHALL log WARN `AppSec request body not received within appsecBodyReadTimeoutSeconds; request blocked. Exclude streaming routes with a bouncerActionRules bypassAppsec rule` through `logger.Debounced` with an interval of 5 seconds, keyed on that message text. The line SHALL carry attrs `ip` (the inbound request's chosen client address), `method`, `host`, `path`, and `timeoutSeconds`.

#### Scenario: Timeout WARN names the escape hatch
- **WHEN** the body read deadline expires
- **THEN** a WARN line names `appsecBodyReadTimeoutSeconds` and `bypassAppsec`
- **AND** it carries `ip`, `method`, `host`, `path`, and `timeoutSeconds`

#### Scenario: Timeout WARN is debounced
- **WHEN** two requests hit the body read deadline within 5 seconds
- **THEN** the WARN is emitted once
- **AND** both requests are blocked
