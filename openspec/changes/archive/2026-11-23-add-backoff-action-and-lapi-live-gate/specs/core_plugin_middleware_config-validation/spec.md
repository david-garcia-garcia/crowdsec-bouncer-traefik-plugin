## ADDED Requirements

### Requirement: Backoff periods are the only gate knobs
`lapiUnhealthyBackOffPeriodSecs`, `appsecUnhealthyBackOffPeriodSecs`, and `modsecUnhealthyBackOffPeriodSecs` SHALL each default to 10. `0` SHALL disable that leg's gate. All three SHALL be in the `requiredInt0` check: a negative period SHALL fail `ValidateParams` with `<Field>: cannot be less than 0`. No leg SHALL have a ratio, threshold, or max-period knob. In `stream` and `alone` the LAPI period SHALL be accepted and ignored.

#### Scenario: Default periods are 10
- **WHEN** the operator omits all three backoff periods
- **THEN** each period is 10 seconds

#### Scenario: Zero disables the AppSec gate
- **WHEN** `appsecUnhealthyBackOffPeriodSecs` is 0
- **THEN** the AppSec Client holds no gate

#### Scenario: Negative ModSec backoff fails
- **WHEN** `modsecUnhealthyBackOffPeriodSecs` is -1
- **THEN** `ValidateParams` returns an error naming `ModsecUnhealthyBackOffPeriodSecs`

#### Scenario: Negative LAPI backoff fails
- **WHEN** `lapiUnhealthyBackOffPeriodSecs` is -1
- **THEN** `ValidateParams` returns an error naming `LapiUnhealthyBackOffPeriodSecs`

#### Scenario: Stream accepts the LAPI period
- **WHEN** `lapiMode` is `stream` and `lapiUnhealthyBackOffPeriodSecs` is 30
- **THEN** `ValidateParams` returns nil

### Requirement: Backoff actions are validated like failure actions
`bouncerLapiBackOffAction`, `bouncerAppsecBackOffAction`, and `bouncerModsecBackOffAction` SHALL accept empty, `passthrough`, `ban`, or `captcha`. `captcha` SHALL need a captcha instance name after owner-fill. Any other value SHALL fail `ValidateParams` with an error naming the Go field. Each key SHALL be per-router and MUST NOT enter any Client ownership key.

#### Scenario: Unknown backoff action fails
- **WHEN** `bouncerAppsecBackOffAction` is `open`
- **THEN** `ValidateParams` returns an error naming `BouncerAppsecBackOffAction`

#### Scenario: Captcha backoff without a captcha instance fails
- **WHEN** `bouncerLapiBackOffAction` is `captcha` and the router has no captcha instance name after owner-fill
- **THEN** `ValidateParams` returns an error naming `BouncerLapiBackOffAction`

#### Scenario: Captcha backoff with an owned captcha passes
- **WHEN** `captchaEnabled` is true, `captchaInstanceName` is omitted, and `bouncerModsecBackOffAction` is `captcha`
- **THEN** `ValidateParams` accepts the action

### Requirement: Failure and backoff actions resolve per leg
An empty or omitted action SHALL resolve per leg, never through one shared default. Failure action: LAPI `ban`, AppSec `passthrough`, ModSec `passthrough`, rate limit `passthrough`. Backoff action: LAPI `ban`, AppSec `passthrough`, ModSec `passthrough`. `New()` defaults SHALL be the same values.

#### Scenario: Shipped defaults
- **WHEN** the operator sets none of the failure or backoff action keys
- **THEN** LAPI failure and backoff actions are `ban`
- **AND** AppSec and ModSec failure and backoff actions are `passthrough`

#### Scenario: Empty AppSec failure action is passthrough
- **WHEN** `bouncerAppsecFailureAction` is an empty string
- **THEN** the effective AppSec failure action is `passthrough`

#### Scenario: Empty LAPI failure action is ban
- **WHEN** `bouncerLapiFailureAction` is an empty string
- **THEN** the effective LAPI failure action is `ban`

## REMOVED Requirements

### Requirement: WAF backoff periods are the only gate knobs
**Reason**: The AppSec default moves from 30 to 10, the ModSec default from 0 to 10, and LAPI `live` / `none` gains the same knob.
**Migration**: "Backoff periods are the only gate knobs" covers all three legs with the new defaults. Operators who want the old behaviour set `appsecUnhealthyBackOffPeriodSecs: 30` and `modsecUnhealthyBackOffPeriodSecs: 0`.
