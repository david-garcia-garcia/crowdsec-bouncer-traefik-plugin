## Purpose

Startup validation for plugin configuration in `pkg/configuration.ValidateParams`.

## Requirements

### Requirement: AppSec URL uses effective scheme
`ValidateParams` SHALL validate the AppSec URL using the effective AppSec scheme: `crowdsecAppsecScheme` when non-empty, otherwise `crowdsecLapiScheme`. It MUST NOT pass `crowdsecLapiScheme` when AppSec has its own scheme.

#### Scenario: Distinct AppSec HTTPS scheme
- **WHEN** `crowdsecAppsecScheme` is `https` and `crowdsecLapiScheme` is `http`
- **THEN** AppSec URL validation uses `https://` format
- **AND** an invalid AppSec host fails at `ValidateParams`

### Requirement: AppSec HTTPS CA validated at startup
When `crowdsecAppsecScheme` is explicitly set to `https` and `crowdsecAppsecTlsInsecureVerify` is false, `ValidateParams` SHALL parse `crowdsecAppsecTlsCertificateAuthority` PEM when provided, rejecting invalid PEM the same way LAPI CA is rejected today.

#### Scenario: Invalid AppSec CA with LAPI HTTP
- **WHEN** `crowdsecLapiScheme` is `http`, `crowdsecAppsecScheme` is `https`, and AppSec CA PEM is garbage
- **THEN** `ValidateParams` returns an error

### Requirement: Alone mode validates captcha templates and logging
In `crowdsecMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when a captcha provider is configured, captcha/ban template files when paths are set, and log level / writable log file path. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, failure action is `captcha`, provider is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode invalid log level
- **WHEN** mode is `alone` and log level is not one of DEBUG/INFO/WARN/ERROR
- **THEN** `ValidateParams` returns an error

### Requirement: Appsec mode without AppSec warns and still starts
`crowdsecMode: appsec` with `crowdsecAppsecEnabled: false` selects no decision source and no WAF leg, so the middleware enforces nothing. `ValidateParams` SHALL log a warning for that combination and SHALL still accept the configuration. It MUST NOT return an error, and it MUST NOT imply `crowdsecAppsecEnabled` on (`crowdsecAppsecHost` defaults to `crowdsec:7422` and `crowdsecAppsecFailureAction` defaults to `ban`, so implying it would ban every request on that router against a listener that may not exist). The warning SHALL be emitted at `WARN`, so it is visible at the default log level, and SHALL name both keys and say that no request is checked in this state.

#### Scenario: Appsec mode with AppSec disabled
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is false
- **THEN** `ValidateParams` returns no error
- **AND** it logs a `WARN` naming `crowdsecMode` and `crowdsecAppsecEnabled` and stating that nothing is enforced

#### Scenario: Appsec mode with AppSec enabled is silent
- **WHEN** `crowdsecMode` is `appsec` and `crowdsecAppsecEnabled` is true
- **THEN** `ValidateParams` logs no such warning

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without provider; `appsec` mode without LAPI key; alone mode captcha/template failures; `GetTemplate` error paths; `validateURL` bad host; `RemediationStatusCode` bounds 99/600; `UpdateMaxFailure: -1` acceptance.

#### Scenario: AppSec captcha without provider rejected
- **WHEN** `crowdsecAppsecFailureAction` is `captcha` and `captchaProvider` is empty
- **THEN** `ValidateParams` returns an error

### Requirement: Redis password file resolved only when Redis is enabled
`ValidateParams` SHALL resolve `RedisCachePassword` and `RedisCachePasswordFile` only when `redisCacheEnabled` is true. When `redisCacheEnabled` is false, a missing, directory, or unreadable `redisCachePasswordFile` MUST NOT fail startup. When `redisCacheEnabled` is true, a non-empty `redisCachePasswordFile` that is missing, a directory, or unreadable SHALL fail startup. An empty password with an empty file path SHALL still be accepted when Redis is enabled.

#### Scenario: Disabled Redis ignores a missing password file
- **WHEN** `redisCacheEnabled` is false and `redisCachePasswordFile` names a path that does not exist
- **THEN** `ValidateParams` returns no error

#### Scenario: Disabled Redis ignores a stale password file
- **WHEN** `redisCacheEnabled` is false and `redisCachePasswordFile` names a directory or an unreadable path
- **THEN** `ValidateParams` returns no error

#### Scenario: Enabled Redis still rejects a missing password file
- **WHEN** `redisCacheEnabled` is true and `redisCachePasswordFile` names a path that does not exist
- **THEN** `ValidateParams` returns an error

#### Scenario: Enabled Redis accepts an empty password with no file
- **WHEN** `redisCacheEnabled` is true, `redisCachePassword` is empty, and `redisCachePasswordFile` is empty
- **THEN** `ValidateParams` returns no error
