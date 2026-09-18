## ADDED Requirements

### Requirement: Provider set requires a loadable captcha template

When `captchaProvider` is set, `ValidateParams` SHALL reject an empty `CaptchaFilePath` and SHALL fail when `GetTemplate` fails for that path. The trigger is a non-empty provider, the same as site, secret, and gate. Error text for the empty path SHALL be `CaptchaFilePath: cannot be empty when CaptchaProvider is set`. A `GetTemplate` failure SHALL be returned as that error. Ban template validation SHALL stay "when path is set". `Client.New` SHALL return the `GetTemplate` error and MUST NOT discard it. The plugin MUST NOT invent a bundled default captcha template. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty captcha path

- **WHEN** `captchaProvider` is set, site, secret, and gate resolve non-empty, and `CaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `CaptchaFilePath: cannot be empty when CaptchaProvider is set`

#### Scenario: Provider set with unreadable captcha path

- **WHEN** `captchaProvider` is set and `CaptchaFilePath` names a missing or unparseable file
- **THEN** `ValidateParams` returns a `GetTemplate` error

#### Scenario: Empty ban path still accepted

- **WHEN** `captchaProvider` is set, captcha path is loadable, and `BanFilePath` is empty
- **THEN** `ValidateParams` returns no error from the ban template

#### Scenario: Client.New returns GetTemplate error

- **WHEN** `Client.New` is called with a non-empty provider and an empty or unreadable captcha template path
- **THEN** `Client.New` returns the `GetTemplate` error
- **AND** it does not return nil with a discarded error

#### Scenario: New returns no handler on empty captcha path

- **WHEN** `New` is called with `captchaProvider` set, site, secret, and gate set, and empty `CaptchaFilePath`
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI

## MODIFIED Requirements

### Requirement: Alone mode validates captcha templates and logging
In `crowdsecMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when a captcha provider is configured, the captcha template when a provider is set (empty `CaptchaFilePath` or a `GetTemplate` failure SHALL fail), the ban template when that path is set, and log level / writable log file path. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation. Empty site or secret after file-then-field lookup SHALL fail even when `CaptchaGateSecret` is set. When `crowdsecAppsecEnabled` is true, it SHALL still validate AppSec URL, AppSec key, and AppSec HTTPS CA.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, failure action is `captcha`, provider is set, `CaptchaGateSecret` is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error that names `CaptchaSiteKey` cannot be empty

#### Scenario: Alone mode invalid log level
- **WHEN** mode is `alone` and log level is not one of DEBUG/INFO/WARN/ERROR
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode empty captcha path
- **WHEN** mode is `alone`, provider is set, site, secret, and gate resolve non-empty, and `CaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `CaptchaFilePath: cannot be empty when CaptchaProvider is set`
