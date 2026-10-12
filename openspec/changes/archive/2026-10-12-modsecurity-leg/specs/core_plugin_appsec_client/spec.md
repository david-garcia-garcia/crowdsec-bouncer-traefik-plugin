## ADDED Requirements

### Requirement: AppSec Client owns the admission gate
When `appsecUnhealthyBackOffPeriodSecs` is greater than 0, `appsec.Client` SHALL hold one `backendbackoff.Gate` from dest utilities `v1.0.7` and MUST NOT copy that package into this repository. Default period SHALL be 30. `0` SHALL build no gate. Query SHALL `Allow` before the AppSec hop. Denied Allow SHALL NOT call AppSec, SHALL NOT apply `bouncerAppsecFailureAction`, and SHALL continue (then ModSec if subscribed). Admitted transport / 5xx / unreachable SHALL `Report` failure then apply FailureAction. A usable verdict SHALL `Report` success. Inbound cancel MUST NOT Report. Client `Close` SHALL Close a non-nil Gate.

#### Scenario: Default 30 builds a gate
- **WHEN** the operator omits `appsecUnhealthyBackOffPeriodSecs`
- **THEN** the AppSec Client holds one Gate with base cooldown 30 seconds

#### Scenario: Gate skip does not call AppSec
- **WHEN** the AppSec Gate denies Allow
- **AND** `bouncerAppsecFailureAction` is `ban`
- **THEN** AppSec is not called
- **AND** the request is not banned for that skip

#### Scenario: Close closes the gate
- **WHEN** an AppSec Client with a Gate is Closed
- **THEN** that Gate is Closed

## MODIFIED Requirements

### Requirement: AppSec is reclaimed by listener identity
When `appsecEnabled` is true, the owning middleware SHALL reclaim an `appsec.Client` with `reclaim.Open` on the process table (30s grace). The reclaim **ownership** key SHALL be derived from the Traefik middleware name plus AppSec scheme, host, path, resolved key, body limit, TLS material, `AppsecHTTPTimeoutSeconds`, and the unhealthy-backoff knobs (`appsecUnhealthyBackOffPeriodSecs`, `appsecUnhealthyMaxBackOffPeriodSecs`, `appsecUnhealthyFailureThreshold`, `appsecUnhealthyFailureRatio`). AppSec instance slot names, `bouncerEnabled`, bounce knobs, LAPI fields, and per-router AppSec failure action MUST NOT be in that key. Two `Open` calls with different middleware names and otherwise identical AppSec knobs SHALL produce two Clients. Two `Open` calls with the same middleware name and identical knobs SHALL Wake the same Client on reload. A change to any keyed AppSec knob SHALL Open a new Client; `AdoptTransport` MUST NOT be the path that applies timeout or TLS changes.

#### Scenario: Two middleware names do not share AppSec
- **WHEN** two owners Open AppSec with different Traefik names and identical URL, key, and body limit
- **THEN** two AppSec Client incarnations exist

#### Scenario: Timeout change is a new Client
- **WHEN** a second Open for the same middleware name changes only `appsecHttpTimeoutSeconds`
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Backoff knob change is a new Client
- **WHEN** a second Open for the same middleware name changes only `appsecUnhealthyBackOffPeriodSecs`
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Same name same knobs Wake
- **WHEN** the holder context for an AppSec ownership key is cancelled and a `New` with the same name and knobs runs before grace ends
- **THEN** the same AppSec Client incarnation is returned
