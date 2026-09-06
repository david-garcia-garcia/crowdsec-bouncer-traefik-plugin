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
When `crowdsecAppsecEnabled` is true, `New` SHALL reclaim an `appsec.Client` with `reclaim.OpenWithGrace` and a 30s grace. The reclaim key SHALL be derived from AppSec scheme, host, path, key, TLS, body limit, and the effective AppSec HTTP timeout (`crowdsecAppsecTimeoutMilliseconds` when greater than zero, otherwise `httpTimeoutSeconds` as a duration). Middleware name, `next`, templates, trusted IPs, Enabled, and LAPI fields MUST NOT be in that key. The create func SHALL return `*reclaim.Wrapped`. `Close` SHALL release idle AppSec HTTP connections.

#### Scenario: Two routers share one AppSec listener
- **WHEN** two `New` calls enable AppSec with the same AppSec URL, key, TLS, and effective AppSec timeout and live constructor contexts
- **THEN** both bouncers use the same `appsec.Client` incarnation

#### Scenario: Different AppSec hosts are isolated
- **WHEN** two `New` calls enable AppSec with different AppSec hosts
- **THEN** two AppSec client incarnations exist

#### Scenario: Same effective timeout shares a client
- **WHEN** one middleware inherits a 10 second AppSec timeout from `httpTimeoutSeconds` and another sets `crowdsecAppsecTimeoutMilliseconds` to 10000 with the same AppSec URL, key, and TLS
- **THEN** both use the same `appsec.Client` incarnation

#### Scenario: Different effective timeouts are isolated
- **WHEN** two `New` calls enable AppSec with the same AppSec URL, key, and TLS but different effective AppSec timeouts
- **THEN** two AppSec client incarnations exist

### Requirement: Empty AppSec key falls back to LAPI key
`appsec.Prepare` SHALL copy `crowdsecLapiKey` into `crowdsecAppsecKey` when the AppSec key is empty, and SHALL copy `crowdsecLapiScheme` into `crowdsecAppsecScheme` when the AppSec scheme is empty. Callers SHALL run `lapi.Prepare` before `appsec.Prepare`.

#### Scenario: Shared bouncer key still works
- **WHEN** the operator sets `crowdsecLapiKey` and omits `crowdsecAppsecKey` with AppSec enabled
- **THEN** AppSec authenticates with that LAPI key

### Requirement: AppSec HTTP timeout is independent of LAPI when set
Public config `crowdsecAppsecTimeoutMilliseconds` SHALL be an integer millisecond timeout for the AppSec HTTP client. Zero or omit SHALL use `httpTimeoutSeconds` (converted to a duration). A value greater than zero SHALL be that many milliseconds. A negative value SHALL be rejected at ValidateParams. LAPI stream/live HTTP and captcha siteverify MUST continue to use `httpTimeoutSeconds` only.

#### Scenario: Omit inherits LAPI timeout
- **WHEN** the operator omits `crowdsecAppsecTimeoutMilliseconds` and sets `httpTimeoutSeconds` to 10
- **THEN** AppSec HTTP calls use a 10 second timeout

#### Scenario: Explicit milliseconds override LAPI timeout
- **WHEN** the operator sets `crowdsecAppsecTimeoutMilliseconds` to 200 and `httpTimeoutSeconds` to 10
- **THEN** AppSec HTTP calls use a 200 millisecond timeout
- **AND** LAPI HTTP calls still use a 10 second timeout

#### Scenario: Negative milliseconds is rejected
- **WHEN** the operator sets `crowdsecAppsecTimeoutMilliseconds` to -1
- **THEN** ValidateParams fails

#### Scenario: Unreachable AppSec with a short timeout and passthrough
- **WHEN** AppSec does not answer within the configured AppSec timeout and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds as allow without waiting the LAPI timeout
