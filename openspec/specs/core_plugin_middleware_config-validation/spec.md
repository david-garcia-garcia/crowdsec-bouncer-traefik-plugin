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
In `crowdsecMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when a captcha provider is configured, captcha/ban template files when paths are set, and log level / writable log file path. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation. Empty site or secret after file-then-field lookup SHALL fail even when `CaptchaGateSecret` is set.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, failure action is `captcha`, provider is set, `CaptchaGateSecret` is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error that names `CaptchaSiteKey` cannot be empty

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

### Requirement: Reject empty captcha site and secret after lookup
When `captchaProvider` is set, `ValidateParams` SHALL resolve `CaptchaSiteKey` and `CaptchaSecretKey` with the same file-then-field lookup used for `CaptchaGateSecret`. After a successful lookup it SHALL reject an empty trimmed string for each field independently, site first. The trigger is a non-empty provider, not a captcha failure action. Error text SHALL be `CaptchaSiteKey: cannot be empty when CaptchaProvider is set` and `CaptchaSecretKey: cannot be empty when CaptchaProvider is set`. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty site and secret
- **WHEN** `captchaProvider` is set, `CaptchaGateSecret` is set, and both site and secret resolve empty
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Only site empty
- **WHEN** `captchaProvider` is set, secret is non-empty, and site resolves empty
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Only secret empty
- **WHEN** `captchaProvider` is set, site is non-empty, and secret resolves empty
- **THEN** `ValidateParams` returns `CaptchaSecretKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Whitespace-only site is empty
- **WHEN** `captchaProvider` is set and site is only whitespace
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Default ban action still rejects empty keys
- **WHEN** `captchaProvider` is set, failure actions are the default `ban`, and site/secret resolve empty
- **THEN** `ValidateParams` returns an error that names the empty site key

#### Scenario: New returns no handler
- **WHEN** `New` is called with `captchaProvider` set, `CaptchaGateSecret` set, and empty site key
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI
