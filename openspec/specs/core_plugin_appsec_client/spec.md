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
When `crowdsecAppsecEnabled` is true, `New` SHALL reclaim an `appsec.Client` with `reclaim.OpenWithGrace` and a 30s grace. The reclaim key SHALL be derived from AppSec scheme, host, path, key, TLS, body limit, and HTTP timeout. Middleware name, `next`, templates, trusted IPs, Enabled, and LAPI fields MUST NOT be in that key. The create func SHALL return `*reclaim.Wrapped`. `Close` SHALL release idle AppSec HTTP connections.

#### Scenario: Two routers share one AppSec listener
- **WHEN** two `New` calls enable AppSec with the same AppSec URL, key, and TLS and live constructor contexts
- **THEN** both bouncers use the same `appsec.Client` incarnation

#### Scenario: Different AppSec hosts are isolated
- **WHEN** two `New` calls enable AppSec with different AppSec hosts
- **THEN** two AppSec client incarnations exist

### Requirement: Empty AppSec key falls back to LAPI key
`appsec.Prepare` SHALL copy `crowdsecLapiKey` into `crowdsecAppsecKey` when the AppSec key is empty, and SHALL copy `crowdsecLapiScheme` into `crowdsecAppsecScheme` when the AppSec scheme is empty. Callers SHALL run `lapi.Prepare` before `appsec.Prepare`.

#### Scenario: Shared bouncer key still works
- **WHEN** the operator sets `crowdsecLapiKey` and omits `crowdsecAppsecKey` with AppSec enabled
- **THEN** AppSec authenticates with that LAPI key

### Requirement: AppSec forward path drains responses for reuse
`Client.Query` SHALL drain the AppSec HTTP response body on every path where `Do` returns a non-nil response, including HTTP 502, 503, and 504, before returning a failure-action result.

#### Scenario: 502 reuses connection
- **WHEN** AppSec returns HTTP 502 and `Query` applies failure action
- **THEN** subsequent queries on the same client reuse one TCP connection

### Requirement: Forwarded request body metadata matches bytes sent
When `Query` forwards a POST body to AppSec, it SHALL omit hop-by-hop headers and stale `Content-Length` / `Transfer-Encoding` from the client copy and SHALL set `Content-Length` to the size of the body bytes actually sent (after truncation when limited).

#### Scenario: Truncated POST has matching Content-Length
- **WHEN** the client POST body exceeds `crowdsecAppsecBodyLimit` and the limit is positive
- **THEN** the AppSec request `Content-Length` equals the truncated byte count

### Requirement: Zero body limit means unlimited forward
When `crowdsecAppsecBodyLimit` is explicitly `0`, `Query` SHALL read and forward the full client POST body to AppSec. It MUST NOT silently downgrade to a bodyless GET.

#### Scenario: Limit zero forwards POST
- **WHEN** `crowdsecAppsecBodyLimit` is `0` and the client sends a POST with a body
- **THEN** AppSec receives a POST whose body equals the full client body
