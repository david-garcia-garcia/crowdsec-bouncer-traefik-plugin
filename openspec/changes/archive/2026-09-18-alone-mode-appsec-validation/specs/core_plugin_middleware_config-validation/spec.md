## ADDED Requirements

### Requirement: Alone mode validates AppSec URL, key file, and HTTPS CA
In `crowdsecMode: alone`, after CAPI credential validation, `ValidateParams` SHALL still apply the same AppSec URL, AppSec key-file, and AppSec HTTPS CA checks as live/stream. It MUST NOT skip those AppSec checks. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks.

#### Scenario: Alone mode invalid AppSec CA
- **WHEN** mode is `alone`, CAPI machine id and password are set, `crowdsecAppsecScheme` is `https`, and AppSec CA PEM is garbage
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode missing AppSec key file
- **WHEN** mode is `alone`, CAPI machine id and password are set, and `crowdsecAppsecKeyFile` names a path that does not exist
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode with CAPI credentials still accepted
- **WHEN** mode is `alone`, CAPI machine id and password are set, and AppSec URL, key-file, and HTTPS CA fields are the defaults
- **THEN** `ValidateParams` returns no error

## MODIFIED Requirements

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without provider; `appsec` mode without LAPI key; alone mode captcha/template failures; alone mode invalid AppSec CA; alone mode missing AppSec key file; `GetTemplate` error paths; `validateURL` bad host; `RemediationStatusCode` bounds 99/600; `UpdateMaxFailure: -1` acceptance.

#### Scenario: AppSec captcha without provider rejected
- **WHEN** `crowdsecAppsecFailureAction` is `captcha` and `captchaProvider` is empty
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode invalid AppSec CA rejected
- **WHEN** mode is `alone`, CAPI credentials are set, `crowdsecAppsecScheme` is `https`, and AppSec CA PEM is garbage
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode missing AppSec key file rejected
- **WHEN** mode is `alone`, CAPI credentials are set, and `crowdsecAppsecKeyFile` names a path that does not exist
- **THEN** `ValidateParams` returns an error
