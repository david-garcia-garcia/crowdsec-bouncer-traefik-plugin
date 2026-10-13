## MODIFIED Requirements

### Requirement: AppSec is reclaimed by listener identity
When `crowdsecAppsecEnabled` is true, `New` SHALL reclaim an `appsec.Client` with `reclaim.Open` on the process table (30s grace). The reclaim key SHALL be derived from AppSec scheme, host, path, key, TLS, body limit, and HTTP timeout. Middleware name, `next`, templates, trusted IPs, Enabled, and LAPI fields MUST NOT be in that key. The Open call SHALL pass `reclaim.Hooks` for Sleep/Wake/Close. `Close` SHALL release idle AppSec HTTP connections.

#### Scenario: Two routers share one AppSec listener
- **WHEN** two `New` calls enable AppSec with the same AppSec URL, key, and TLS and live constructor contexts
- **THEN** both bouncers use the same `appsec.Client` incarnation

#### Scenario: Different AppSec hosts are isolated
- **WHEN** two `New` calls enable AppSec with different AppSec hosts
- **THEN** two AppSec client incarnations exist
