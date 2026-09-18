## Purpose

Admits CrowdSec AppSec HTTP through the published `backendbackoff` Gate so a dead listener is not contacted on every request, without changing today's FailureAction enums.

## Requirements

### Requirement: AppSec Clients own one published Gate
An `appsec.Client` SHALL construct one `backendbackoff.Gate` at create time from the shared plugin backoff knobs. The package SHALL import `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff` and MUST NOT copy that package into `pkg/`, MUST NOT add `pkg/health`, and MUST NOT import traefik-modsecurity. Sleep and Wake MUST NOT touch the Gate. The knobs MUST NOT join the AppSec reclaim key; a later `New` that differs only on those knobs SHALL reuse the same Client (silent first-wins). Last `New` still `AdoptTransport`s TLS/timeout.

#### Scenario: AppSec Client has a Gate
- **WHEN** an AppSec Client is constructed
- **THEN** that Client owns one Gate built from the plugin backoff knobs

#### Scenario: Backoff knobs do not split the Client
- **WHEN** two `New` calls enable AppSec with the same URL, key, and body limit and differ only on a backoff knob
- **THEN** both constructors use the same `appsec.Client` incarnation

### Requirement: Each AppSec Do is admitted before the HTTP attempt
Before each AppSec `Do`, the Client SHALL call `Allow` with the inbound request `Context` and the AppSec URL stem the Client already composes for that attempt (`scheme` + `host` + `path`). The key MUST NOT be the client address and MUST NOT be the AppSec reclaim key. Client address on `X-Crowdsec-Appsec-Ip` SHALL stay the `ip` argument already chosen by `pkg/ip.GetRemoteIP`. Host on the existing AppSec header copy SHALL stay the inbound request `Host`. The call MUST NOT sleep on Allow's wait; it SHALL Debug-log that wait. Constructor context and `context.Background()` MUST NOT be used for Allow. An inbound unreadable body that never `Do`s MUST NOT call Allow or Report; today's FailureAction on that path SHALL stay.

#### Scenario: Denied Do does not hit AppSec
- **WHEN** Allow returns `ok=false` and `err=nil` for the AppSec URL stem
- **THEN** no HTTP request is sent to AppSec
- **AND** `crowdsecAppsecFailureAction` is applied
- **AND** the error message is not `unreachable`

#### Scenario: Unreadable body ban never Allows
- **WHEN** the request body cannot be buffered, the method is POST, PUT, or PATCH, and `crowdsecAppsecFailureAction` is `ban`
- **THEN** Allow is not called
- **AND** AppSec is not contacted
- **AND** the request is dropped

#### Scenario: Unreadable body passthrough still Allows the headers-only GET
- **WHEN** the request body cannot be buffered, the method is POST, PUT, or PATCH, and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** Allow runs before the headers-only AppSec GET

### Requirement: Denied or Allow-error uses today's AppSec FailureAction
A denied Allow or an Allow error SHALL take today's `crowdsecAppsecFailureAction` path with no `Do`. No new action enum SHALL be added. Denied Allows MUST NOT be Reported.

#### Scenario: Denied Do with passthrough
- **WHEN** Allow denies the AppSec URL stem and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds as allow
- **AND** AppSec is not contacted

### Requirement: Admitted AppSec attempts Report only HTTP-class failures
After an admitted `Do`, the Client SHALL `Report` on the same URL stem. Report failure SHALL be a `Do` error, listener HTTP 502/503/504, or HTTP 500. After an admitted `Do`, response-body io errors, parse, 200/403 envelopes, and oversized-body handling SHALL Report success (the backend answered). FailureAction on those paths MUST NOT change. An inbound unreadable body that never `Do`s MUST NOT Report.

#### Scenario: HTTP 500 Reports failure
- **WHEN** an admitted `Do` returns HTTP 500
- **THEN** Report is called with failure
- **AND** `crowdsecAppsecFailureAction` is applied

#### Scenario: Response-body io Reports success
- **WHEN** an admitted `Do` returns a body that then fails with a response-body io error
- **THEN** Report is called with success
- **AND** `crowdsecAppsecFailureAction` is still applied
- **AND** the error string keeps `appsecQuery:readBody`

#### Scenario: Success Report recovers
- **WHEN** the Gate is OPEN after failures
- **AND** a later admitted `Do` returns HTTP 200 allow
- **THEN** Report is called with success
- **AND** a following Query is admitted again

### Requirement: Client Close closes the Gate
`appsec.Client.Close` SHALL close a non-nil Gate. Close MUST remain safe to call more than once.

#### Scenario: AppSec Close closes the Gate
- **WHEN** an AppSec Client is Closed
- **THEN** a later Allow on that Gate does not admit
