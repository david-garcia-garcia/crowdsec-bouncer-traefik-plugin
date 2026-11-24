## ADDED Requirements

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

## REMOVED Requirements

### Requirement: ModSec Client owns the admission gate
**Reason**: The default period moves from `0` (no gate) to `10`. The block is split so that each behaviour has its own requirement.
**Migration**: "ModSec Client holds one admission gate" and "ModSec backoff logs once per transition" carry every rule of the removed block, with the new default. Operators who want no ModSec gate set `modsecUnhealthyBackOffPeriodSecs: 0`.
