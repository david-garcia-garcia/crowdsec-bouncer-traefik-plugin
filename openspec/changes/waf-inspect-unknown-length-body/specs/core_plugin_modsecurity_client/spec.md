## MODIFIED Requirements

### Requirement: ModSecurity is reclaimed by sidecar identity
When `modsecEnabled` is true, the owning middleware SHALL reclaim a `modsecurity.Client` with `reclaim.Open` on the process table. The reclaim ownership key SHALL be derived from the Traefik middleware name plus `modsecUrl`, `modsecHttpTimeoutSeconds`, `modsecBodyLimit`, `modsecBodyReadTimeoutSeconds`, and `modsecUnhealthyBackOffPeriodSecs`. Slot name, `bouncerEnabled`, bounce knobs, LAPI fields, AppSec fields, captcha fields, and per-router `bouncerModsecFailureAction` MUST NOT be in that key. Two `Open` calls with different middleware names and otherwise identical ModSec knobs SHALL produce two Clients. A change to any keyed ModSec knob SHALL Open a new Client.

#### Scenario: Two middleware names do not share ModSec
- **WHEN** two owners Open ModSec with different Traefik names and identical `modsecUrl`
- **THEN** two ModSec Client incarnations exist

#### Scenario: Backoff knob change is a new Client
- **WHEN** a second Open for the same middleware name changes only `modsecUnhealthyBackOffPeriodSecs`
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Body read timeout change is a new Client
- **WHEN** a second Open for the same middleware name changes only `modsecBodyReadTimeoutSeconds`
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Same name same knobs Wake
- **WHEN** the holder context for a ModSec ownership key is cancelled and a `New` with the same name and knobs runs before grace ends
- **THEN** the same ModSec Client incarnation is returned
