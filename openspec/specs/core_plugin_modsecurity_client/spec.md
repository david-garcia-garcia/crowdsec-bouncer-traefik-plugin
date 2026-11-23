## Purpose

`package modsecurity` owns the reclaim value for one OWASP CRS sidecar listener. It copies requests for inspection and does not speak CrowdSec AppSec JSON.

## Requirements

### Requirement: ModSecurity lives in package modsecurity
`package modsecurity` SHALL own the reclaim value for one CRS sidecar listener. The exported type SHALL be `Client`. The package MUST NOT import `pkg/appsec` or `pkg/lapi` and MUST NOT speak CrowdSec AppSec JSON (`X-Crowdsec-Appsec-*` or AppSec `action` envelopes).

#### Scenario: Bouncer inspects through modsecurity.Client
- **WHEN** `pkg/bouncer` compiles against this package
- **THEN** a ModSec inspect call resolves on `modsecurity.Client`
- **AND** the call does not go through `appsec.Client`

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

### Requirement: Empty ModSec instance name fills only when owned
When `modsecEnabled` is true and the trimmed `modsecInstanceName` is empty, `Prepare` SHALL set the instance name to this middleware's Traefik name. When `modsecEnabled` is false, an empty name SHALL stay empty.

#### Scenario: Owner omit fills to Traefik name
- **WHEN** `modsecEnabled` is true and `modsecInstanceName` is omitted
- **AND** the Traefik middleware name is `cs-owner`
- **THEN** the published ModSec alias is `alias:modsec:cs-owner`

#### Scenario: Subscriber omit does not fill
- **WHEN** `modsecEnabled` is false, `bouncerEnabled` is true, and `modsecInstanceName` is omitted
- **THEN** the name stays empty
- **AND** the middleware does not Watch ModSec

### Requirement: The plugin has no method list for bodies
The plugin MUST NOT reject a request because of its method and body. A readable body up to `modsecBodyLimit` SHALL be forwarded to the sidecar on every method, with a `Content-Length` rebuilt from the forwarded bytes. CRS decides what a body means (rules 920170 and 920171 block a body on GET and HEAD). An operator who wants to block a body on another method SHALL add a `SecRule` to the sidecar.

#### Scenario: GET with a body reaches the sidecar
- **WHEN** a GET carries a readable body
- **THEN** the sidecar receives that body
- **AND** the plugin does not answer HTTP 400 itself

### Requirement: ModSec body limit
Omitted `modsecBodyLimit` SHALL be 8388608 (8 MiB). There SHALL be no unlimited value because the inbound body is held in memory: when `modsecEnabled` is true, a limit below 1 SHALL fail `New` with `ModsecBodyLimit: cannot be less than 1`. A middleware that does not own ModSec SHALL NOT validate this knob. Exceeding the limit SHALL be HTTP 413 and MUST NOT call the sidecar.

#### Scenario: Omitted limit is 8 MiB
- **WHEN** `modsecBodyLimit` is omitted
- **AND** the client POST exceeds 8388608 bytes
- **THEN** the response is HTTP 413
- **AND** the sidecar is not called

#### Scenario: Zero is rejected when owned
- **WHEN** `modsecEnabled` is true and `modsecBodyLimit` is `0`
- **THEN** `New` fails with `ModsecBodyLimit: cannot be less than 1`

### Requirement: ModSec Client holds one admission gate
When `modsecUnhealthyBackOffPeriodSecs` is greater than 0, the Client SHALL hold one `backendbackoff.Gate` from dest utilities and MUST NOT copy that package into this repository. Default period SHALL be `10`. `0` SHALL build no gate. The period SHALL be the only knob: the trip rule is fixed in `pkg/admission` (`TripFailures` 5, `FailureRatio` 0.30), the cooldown stays at the period, and `Jitter` and `TTL` MUST NOT be set. `Close` SHALL Close a non-nil Gate.

#### Scenario: Omitted backoff builds a 10 second gate
- **WHEN** the operator omits `modsecUnhealthyBackOffPeriodSecs`
- **THEN** the Client holds one Gate with cooldown 10 seconds

#### Scenario: Zero builds no gate
- **WHEN** `modsecUnhealthyBackOffPeriodSecs` is 0 and the sidecar returns HTTP 500 on every request
- **THEN** every request applies `bouncerModsecFailureAction`
- **AND** every request still calls the sidecar

#### Scenario: Positive backoff builds one gate
- **WHEN** `modsecUnhealthyBackOffPeriodSecs` is 30
- **THEN** the Client holds one Gate
- **AND** Client Close closes that Gate

#### Scenario: Fifth failure in a row trips the gate
- **WHEN** the gate is on and the sidecar fails 5 times in a row
- **THEN** the sixth request does not call the sidecar

#### Scenario: Cooldown does not grow
- **WHEN** a probe after the cooldown fails
- **THEN** the next cooldown is the same period

### Requirement: ModSec backoff logs once per transition
The ModSec gate SHALL log one WARN `crowdsec modsec backoff started` (with `retryIn`) on the first skipped request after a trip, and one INFO `crowdsec modsec backoff ended` when the probe admitted during the backoff reports success. Skipped requests MUST NOT log one line each. A success from a request admitted before the trip MUST NOT log `backoff ended`. `pkg/admission` owns both lines for the AppSec, ModSec, and LAPI Clients.

#### Scenario: Backoff logs once per transition
- **WHEN** the ModSec gate trips and several later requests are skipped
- **THEN** exactly one `crowdsec modsec backoff started` line is logged
- **AND** after a probe succeeds exactly one `crowdsec modsec backoff ended` line is logged
