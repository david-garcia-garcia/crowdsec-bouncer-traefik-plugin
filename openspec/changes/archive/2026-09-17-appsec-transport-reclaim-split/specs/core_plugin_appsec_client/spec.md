## MODIFIED Requirements

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

## ADDED Requirements

### Requirement: AppSec HTTP transport is replaceable after Open
`Client` SHALL store AppSec HTTP+auth (HTTP client, API key, timeout, AppSec TLS extras) as `atomic.Value`. After `Open` bind, the constructor SHALL call `AdoptTransport` with that config: Store the new transport and idle-close the previous HTTP client. Remaining write-once Client scalar fields MUST NOT become mutable. The Client field that holds that transport MUST NOT be `atomic.Pointer[T]`. `Query` SHALL send the API key and HTTP round-trip from the stored transport.

#### Scenario: AdoptTransport replaces HTTP without a new Client
- **WHEN** a later `New` reuses a live AppSec Client and calls `AdoptTransport` with a different TLS or HTTP timeout
- **THEN** later AppSec requests use the new HTTP client
- **AND** the previous HTTP client’s idle connections are closed
- **AND** an INFO line names the replaced transport fields
