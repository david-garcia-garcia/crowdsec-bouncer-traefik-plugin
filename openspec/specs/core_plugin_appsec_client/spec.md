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
When `crowdsecAppsecEnabled` is true, `New` SHALL reclaim an `appsec.Client` with `reclaim.Open` on the process table (30s grace). The reclaim key SHALL be derived from AppSec scheme, host, path, key, and body limit. AppSec TLS, HTTP timeout, middleware name, `next`, templates, trusted IPs, Enabled, LAPI fields, and per-router AppSec failure action MUST NOT be in that key. The Open call SHALL pass `reclaim.Hooks` for Sleep/Wake/Close. `Close` SHALL release idle AppSec HTTP connections.

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
`appsec.Prepare` SHALL copy `crowdsecLapiKey` into `crowdsecAppsecKey` when the AppSec key is empty, and SHALL copy `crowdsecLapiScheme` into `crowdsecAppsecScheme` when the AppSec scheme is empty. Callers SHALL run `lapi.Prepare` before `appsec.Prepare`.

#### Scenario: Shared bouncer key still works
- **WHEN** the operator sets `crowdsecLapiKey` and omits `crowdsecAppsecKey` with AppSec enabled
- **THEN** AppSec authenticates with that LAPI key

### Requirement: AppSec User-Agent includes plugin version
AppSec Query SHALL set the outbound `User-Agent` to `Crowdsec-Bouncer-Traefik-Plugin/` plus the plugin version passed into the AppSec Client. It MUST NOT leave that header empty when a version was passed.

#### Scenario: Query User-Agent matches constructed version
- **WHEN** an AppSec Client constructed with plugin version `v9.9.9-test` queries the AppSec listener
- **THEN** the outbound request `User-Agent` is `Crowdsec-Bouncer-Traefik-Plugin/v9.9.9-test`
