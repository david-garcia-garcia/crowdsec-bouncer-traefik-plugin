## ADDED Requirements

### Requirement: WAF body read timeouts are per leg and at least 1
`Config` SHALL expose `AppsecBodyReadTimeoutSeconds` (`appsecBodyReadTimeoutSeconds`) and `ModsecBodyReadTimeoutSeconds` (`modsecBodyReadTimeoutSeconds`). `CreateConfig` and `configuration.New` SHALL default each to 30. `ValidateParams` SHALL reject either one below 1 (`<Field>: cannot be less than 1`); there is no value that disables the deadline. There SHALL be no shared, unprefixed body read timeout key. Setting one MUST NOT move the other.

#### Scenario: Defaults are thirty
- **WHEN** the operator omits both keys
- **THEN** `CreateConfig` leaves each knob at 30
- **AND** `ValidateParams` returns no error

#### Scenario: Zero is invalid
- **WHEN** `modsecBodyReadTimeoutSeconds` is 0
- **THEN** `ValidateParams` returns an error that names `ModsecBodyReadTimeoutSeconds` and `cannot be less than 1`

#### Scenario: One knob does not move the other
- **WHEN** `appsecBodyReadTimeoutSeconds` is 5 and `modsecBodyReadTimeoutSeconds` is omitted
- **THEN** the AppSec body read timeout is 5 and the ModSec one stays 30

### Requirement: appsecBodyLimit is not range-checked
`ValidateParams` MUST NOT reject any `appsecBodyLimit` value. A value of 0 or less SHALL mean the 10485760-byte default (`core_plugin_appsec_client`). `modsecBodyLimit` keeps its own check (`ModsecBodyLimit: cannot be less than 1`).

#### Scenario: Negative AppSec body limit is accepted
- **WHEN** `appsecBodyLimit` is -1 and the rest of the config is valid
- **THEN** `ValidateParams` returns nil

#### Scenario: Zero ModSec body limit is still rejected
- **WHEN** `modsecEnabled` is true, `modsecUrl` is valid, and `modsecBodyLimit` is 0
- **THEN** `ValidateParams` returns an error naming `ModsecBodyLimit`
