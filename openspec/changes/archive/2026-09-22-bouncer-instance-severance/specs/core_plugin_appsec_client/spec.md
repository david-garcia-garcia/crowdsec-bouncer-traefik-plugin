## MODIFIED Requirements

### Requirement: AppSec is reclaimed by listener identity
When `crowdsecAppsecEnabled` is true, the owning middleware SHALL reclaim an `appsec.Client` with `reclaim.Open` on the process table (30s grace). The reclaim **ownership** key SHALL be derived from the Traefik middleware name plus AppSec scheme, host, path, resolved key, body limit, TLS material, and effective HTTP timeout. AppSec instance slot names, `enabled`, bounce knobs, LAPI fields, and per-router AppSec failure action MUST NOT be in that key. Two `Open` calls with different middleware names and otherwise identical AppSec knobs SHALL produce two Clients. Two `Open` calls with the same middleware name and identical knobs SHALL Wake the same Client on reload. A change to any keyed AppSec knob SHALL Open a new Client; `AdoptTransport` MUST NOT be the path that applies timeout or TLS changes.

#### Scenario: Two middleware names do not share AppSec
- **WHEN** two owners Open AppSec with different Traefik names and identical URL, key, and body limit
- **THEN** two AppSec Client incarnations exist

#### Scenario: Timeout change is a new Client
- **WHEN** a second Open for the same middleware name changes only effective HTTP timeout
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Same name same knobs Wake
- **WHEN** the holder context for an AppSec ownership key is cancelled and a `New` with the same name and knobs runs before grace ends
- **THEN** the same AppSec Client incarnation is returned

### Requirement: AppSec HTTP transport is replaceable after Open
**MODIFIED clause**: `AdoptTransport` MAY still replace HTTP for the **same** Client incarnation when the ownership key unchanged; when ownership key changes, a new Client owns its transport. `Query` SHALL send from the stored transport on the loaded Client.

#### Scenario: Same-incarnation TLS adopt still allowed
- **WHEN** a reload Wake reuses the same AppSec ownership key and calls `AdoptTransport` with updated TLS on that incarnation
- **THEN** later queries use the adopted transport without a second reclaim Open key
