## ADDED Requirements

### Requirement: Enabled AppSec requires a listener host
When `crowdsecAppsecEnabled` is true, `ValidateParams` SHALL reject an empty `crowdsecAppsecHost` and any AppSec URL that `http.NewRequest` accepts only because the host is missing. When `crowdsecAppsecEnabled` is false, `ValidateParams` MUST NOT fail solely because `crowdsecAppsecHost` is empty. Shared LAPI URL validation MUST keep accepting an empty host the same way it does today.

#### Scenario: Enabled AppSec with empty host is rejected
- **WHEN** `crowdsecAppsecEnabled` is true and `crowdsecAppsecHost` is empty
- **THEN** `ValidateParams` returns an error

#### Scenario: Disabled AppSec with empty host is accepted
- **WHEN** `crowdsecAppsecEnabled` is false, `crowdsecAppsecHost` is empty, and the rest of the config is valid
- **THEN** `ValidateParams` returns nil
