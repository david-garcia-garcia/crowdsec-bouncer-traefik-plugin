## ADDED Requirements

### Requirement: Ban template empty or unloadable warns at Bouncer New
When `BouncerBanFilePath` is empty or `GetTemplate` fails for that path, `ValidateParams` MUST NOT fail `New`. `bouncer.New` SHALL emit one WARN `crowdsec bouncer ban template unavailable` (`reason` `empty` or `unloadable`), keep the ban template unset, and succeed. Ban remediation SHALL write the remediation status with an empty body. The plugin MUST NOT invent a bundled default ban page. This WARN SHALL NOT repeat on every request.

#### Scenario: Empty ban path warns and stays bodyless
- **WHEN** `BouncerBanFilePath` is empty
- **THEN** `ValidateParams` returns no error from the ban template
- **AND** `bouncer.New` succeeds
- **AND** the log contains WARN `crowdsec bouncer ban template unavailable` with `reason` `empty`
- **AND** a GET ban writes the remediation status with an empty body

#### Scenario: Unloadable ban path warns and stays bodyless
- **WHEN** `BouncerBanFilePath` names a missing or unparseable file
- **THEN** `ValidateParams` returns no error from the ban template
- **AND** `bouncer.New` succeeds
- **AND** the log contains WARN `crowdsec bouncer ban template unavailable` with `reason` `unloadable`
- **AND** a GET ban writes the remediation status with an empty body

## MODIFIED Requirements

### Requirement: Alone mode validates captcha templates and logging
In `lapiMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when `captchaEnabled` is true, and log level / writable log file path. Empty `CaptchaFilePath` or a `GetTemplate` failure MUST NOT fail `ValidateParams`. An unloadable ban template MUST NOT fail `ValidateParams`. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation. Empty site or secret after file-then-field lookup SHALL fail even when `CaptchaGateSecret` is set. When `appsecEnabled` is true, it SHALL still validate AppSec URL, AppSec key, and AppSec HTTPS CA.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, `captchaEnabled` is true, failure action is `captcha`, provider is set, `CaptchaGateSecret` is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error that names `CaptchaSiteKey` cannot be empty

#### Scenario: Alone mode invalid log level
- **WHEN** mode is `alone` and log level is not one of DEBUG/INFO/WARN/ERROR
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode empty captcha path
- **WHEN** mode is `alone`, `captchaEnabled` is true, provider is set, site, secret, and gate resolve non-empty, and `CaptchaFilePath` is empty
- **THEN** `ValidateParams` returns no error from the captcha template

### Requirement: Instance open versus subscribe validation
`ValidateParams` SHALL enforce the open-vs-subscribe matrix for each leg (LAPI, AppSec, and captcha). When `bouncerEnabled` is false and the leg enable flag is false, a non-empty instance name, API key, or client certificate for that leg SHALL fail validation (E2). Captcha E2 is a leftover `captchaInstanceName` (not leftover owner-read `captcha*` keys). When `bouncerEnabled` is true, the leg enable flag is false, and the instance name is omitted after prepopulation rules, the bouncer SHALL NOT subscribe and validation SHALL succeed without treating the leg as open (E3). When a LAPI or AppSec enable flag is true and neither API key nor client certificate can build that client, `ValidateParams` or subsequent `Open` failure SHALL fail `New` for that middleware. When `captchaEnabled` is true, owner-style captcha checks SHALL fail `New` if provider, keys, or gate secret cannot build the client. An empty or unloadable captcha template MUST NOT fail `New`.

#### Scenario: Leftover instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `lapiEnabled` is false, and `lapiInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Bouncer with LAPI leg off and no name succeeds
- **WHEN** `bouncerEnabled` is true, `lapiEnabled` is false, AppSec is disabled, and `lapiInstanceName` is omitted
- **THEN** `ValidateParams` returns no error

#### Scenario: Leftover captcha instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `captchaEnabled` is false, and `captchaInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

### Requirement: ValidateParams test coverage for mode and helper gaps
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without a captcha instance name; **LAPI disabled AppSec-only path (replaces appsec mode without LAPI key)**; alone mode captcha key failures; empty or unloadable captcha and ban templates that warn and do not fail `New`; `GetTemplate` error paths; `validateURL` bad host; `BouncerRemediationStatusCode` bounds 99/600; `LapiUpdateMaxFailure: -1` acceptance; **instance name E2/E3 cases including captcha**.

#### Scenario: AppSec captcha without instance name rejected
- **WHEN** `bouncerAppsecFailureAction` is `captcha` and `captchaInstanceName` is empty after owner-fill rules
- **THEN** `ValidateParams` returns an error

### Requirement: Provider set requires a loadable captcha template
When `captchaEnabled` is true, `ValidateParams` MUST NOT fail `New` because `CaptchaFilePath` is empty or `GetTemplate` fails for that path. Site key, secret, and gate secret stay required when a captcha provider is set. The captcha owner SHALL emit one WARN `crowdsec captcha template unavailable` when the captcha file is empty (`reason` `empty`) or not loadable (`reason` `unloadable`), succeed, and leave the client not valid so a captcha remediation uses the ban path. The plugin MUST NOT invent a bundled default captcha template. Bounce-only (`captchaEnabled` false) MUST NOT read unused default `/captcha.html` and MUST NOT emit this WARN.

#### Scenario: Provider set with empty captcha path
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, site, secret, and gate resolve non-empty, and `CaptchaFilePath` is empty
- **THEN** `ValidateParams` returns no error from the captcha template
- **AND** `New` returns a handler
- **AND** the log contains WARN `crowdsec captcha template unavailable` with `reason` `empty`

#### Scenario: Provider set with unreadable captcha path
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, and `CaptchaFilePath` names a missing or unparseable file
- **THEN** `ValidateParams` returns no error from the captcha template
- **AND** `New` returns a handler
- **AND** the log contains WARN `crowdsec captcha template unavailable` with `reason` `unloadable`

#### Scenario: Empty ban path still accepted
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, captcha path is loadable, and `BouncerBanFilePath` is empty
- **THEN** `ValidateParams` returns no error from the ban template

#### Scenario: Client.New succeeds with Valid false
- **WHEN** `Client.New` is called with a non-empty provider and an empty or unreadable captcha template path
- **THEN** `Client.New` returns no error
- **AND** the client is not valid
- **AND** the log contains WARN `crowdsec captcha template unavailable`

#### Scenario: New returns a handler on empty captcha path
- **WHEN** `New` is called with `captchaEnabled` true, `captchaProvider` set, site, secret, and gate set, and empty `CaptchaFilePath`
- **THEN** `New` returns a handler
- **AND** a captcha remediation uses the ban path

#### Scenario: Bounce-only unused default is not warned
- **WHEN** `captchaEnabled` is false, `bouncerEnabled` is true, and leftover `CaptchaFilePath` is `/captcha.html`
- **THEN** `ValidateParams` returns no error from the captcha template
- **AND** the log MUST NOT contain WARN `crowdsec captcha template unavailable`
