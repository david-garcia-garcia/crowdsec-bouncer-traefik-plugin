## ADDED Requirements

### Requirement: Shared backend backoff knobs default to the published package
Public config SHALL expose one shared knob set applied independently when each Client constructs its Gate: `backendBackoffFailureRatio` (default `0.30`), `backendBackoffTripFailures` (default `5`), `backendBackoffBaseCooldownSeconds` (default `1`), `backendBackoffMaxCooldownSeconds` (default `10`), `backendBackoffJitter` (default `0.10`), `backendBackoffTTLSeconds` (default `60`). `CreateConfig` / `configuration.New` SHALL set those defaults so a fully populated Config is always passed and a zero `Jitter` is not an accidental omit. There SHALL be no product enabled flag. `Jitter` `0` disables jitter only. README SHALL document the keys and those defaults. LAPI and AppSec MUST NOT grow separate knob sets.

#### Scenario: Omitted knobs use package defaults
- **WHEN** the operator omits every `backendBackoff*` key
- **THEN** `CreateConfig` supplies FailureRatio `0.30`, TripFailures `5`, BaseCooldown `1s`, MaxCooldown `10s`, Jitter `0.10`, and TTL `60s`

#### Scenario: Explicit jitter zero disables jitter only
- **WHEN** the operator sets `backendBackoffJitter` to `0` and leaves the other knobs at defaults
- **THEN** `ValidateParams` accepts the config
- **AND** the constructed Gates disable jitter only

### Requirement: ValidateParams rejects values the published Gate would reject
`ValidateParams` SHALL reject a backoff Config that `backendbackoff.New` would reject: FailureRatio not in `(0, 1)` after the library's zero-fill, TripFailures `< 1` after zero-fill, BaseCooldown `≤ 0`, MaxCooldown `<` BaseCooldown, Jitter not in `[0, 1)`, or TTL `< 1s`. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI. Validation SHALL run in every `crowdsecMode`.

#### Scenario: FailureRatio out of range is rejected
- **WHEN** `backendBackoffFailureRatio` is `1.5`
- **THEN** `ValidateParams` returns an error

#### Scenario: MaxCooldown below BaseCooldown is rejected
- **WHEN** `backendBackoffBaseCooldownSeconds` is `10` and `backendBackoffMaxCooldownSeconds` is `1`
- **THEN** `ValidateParams` returns an error

#### Scenario: New returns no handler
- **WHEN** `New` is called with `backendBackoffFailureRatio` `1.5` and an otherwise valid config
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI
