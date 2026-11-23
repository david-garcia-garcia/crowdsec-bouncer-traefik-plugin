## ADDED Requirements

### Requirement: AppSec Client holds one admission gate
When `appsecUnhealthyBackOffPeriodSecs` is greater than 0, `appsec.Client` SHALL hold one `backendbackoff.Gate` from dest utilities and MUST NOT copy that package into this repository. Default period SHALL be 10. `0` SHALL build no gate. A negative period SHALL fail `New`. The period SHALL be the only knob: the trip rule is fixed in `pkg/admission` (`TripFailures` 5, `FailureRatio` 0.30) and the cooldown stays at the period. `Close` SHALL Close a non-nil Gate.

#### Scenario: Default 10 builds a gate
- **WHEN** the operator omits `appsecUnhealthyBackOffPeriodSecs`
- **THEN** the AppSec Client holds one Gate with base cooldown 10 seconds

#### Scenario: Zero builds no gate
- **WHEN** `appsecUnhealthyBackOffPeriodSecs` is 0
- **THEN** the AppSec Client holds no Gate

#### Scenario: Fifth failure in a row trips the gate
- **WHEN** the gate is on and AppSec fails 5 admitted requests in a row with `bouncerAppsecFailureAction` `ban`
- **THEN** those 5 requests are banned
- **AND** the sixth request does not call AppSec and gets `bouncerAppsecBackOffAction`, not the failure action

#### Scenario: Close closes the gate
- **WHEN** an AppSec Client with a Gate is Closed
- **THEN** that Gate is Closed

### Requirement: AppSec admission comes after the body read
`Query` SHALL read the client body first and then `Allow` before the AppSec hop, so a client body error or disconnect never holds an admitted ticket. An admission error other than inbound cancel SHALL apply FailureAction. A denied `Allow` SHALL NOT call AppSec, SHALL NOT apply `bouncerAppsecFailureAction`, and SHALL return `ErrGateSkip`. The bouncer answers it with the router's `bouncerAppsecBackOffAction` (`core_plugin_appsec_failure-action`).

#### Scenario: Gate skip does not call AppSec
- **WHEN** the AppSec Gate denies Allow
- **AND** `bouncerAppsecFailureAction` is `ban` and `bouncerAppsecBackOffAction` is omitted
- **THEN** AppSec is not called
- **AND** the request is not banned for that skip

#### Scenario: Client disconnect holds no ticket
- **WHEN** the client disconnects while its readable body is buffered
- **THEN** `Allow` is not called for that request

### Requirement: AppSec gate records the listener's health
An admitted transport failure, HTTP 500, any listener status other than 200, 401, 403, and 500, or an AppSec response-body io error SHALL `Report` failure, then apply FailureAction. HTTP 401 SHALL `Report` success (a wrong key is a configuration error, not an outage) and still apply FailureAction. A usable verdict SHALL `Report` success. An inbound cancel MUST NOT Report.

#### Scenario: HTTP 401 does not spend gate budget
- **WHEN** the AppSec listener answers HTTP 401 on every request
- **THEN** the AppSec Gate never trips
- **AND** every request still uses `bouncerAppsecFailureAction`

#### Scenario: HTTP 500 spends gate budget
- **WHEN** the AppSec listener answers HTTP 500 on 5 admitted requests in a row
- **THEN** the AppSec Gate trips

### Requirement: AppSec backoff logs once per transition
The AppSec gate SHALL log one WARN `crowdsec appsec backoff started` (with `retryIn`) on the first skipped request after a trip, and one INFO `crowdsec appsec backoff ended` when the probe admitted during the backoff reports success. Skipped requests MUST NOT log one line each. A success from a request admitted before the trip MUST NOT log `backoff ended`. `pkg/admission` owns both lines for the AppSec, ModSec, and LAPI Clients.

#### Scenario: Backoff logs once per transition
- **WHEN** the AppSec gate trips and several later requests are skipped
- **THEN** exactly one `crowdsec appsec backoff started` line is logged
- **AND** after a probe succeeds exactly one `crowdsec appsec backoff ended` line is logged

## REMOVED Requirements

### Requirement: AppSec Client owns the admission gate
**Reason**: The default period moves from 30 to 10, and a denied admission is now answered with the per-router `bouncerAppsecBackOffAction` instead of always continuing. The block is split so that each behaviour has its own requirement.
**Migration**: "AppSec Client holds one admission gate", "AppSec admission comes after the body read", "AppSec gate records the listener's health", and "AppSec backoff logs once per transition" carry every rule of the removed block, with the new default and the skip answer.
