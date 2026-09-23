## ADDED Requirements

### Requirement: Captcha own-axis keys and default
`Config` SHALL expose `captchaEnabled` (Go `CaptchaEnabled`, default false) and `captchaInstanceName` (Go `CaptchaInstanceName`, default empty). `CreateConfig` MUST NOT default `captchaEnabled` true from a set `bouncerCaptchaProvider`. Owner-style captcha checks (provider, site/secret keys, gate secret, loadable template, custom-validate body tokens) SHALL run only when `captchaEnabled` is true. A subscriber leftover `bouncerCaptcha*` MUST NOT fail those checks.

#### Scenario: Default is false
- **WHEN** the operator omits `captchaEnabled`
- **THEN** `CreateConfig` leaves it false
- **AND** a set `bouncerCaptchaProvider` does not own captcha

#### Scenario: Subscriber leftover keys do not fail ValidateParams
- **WHEN** `captchaEnabled` is false, `bouncerEnabled` is true, `captchaInstanceName` is `shared`, and leftover `bouncerCaptchaProvider` is set with empty keys
- **THEN** `ValidateParams` returns no error from owner-style captcha checks

#### Scenario: Owner missing keys fail
- **WHEN** `captchaEnabled` is true and site or secret resolves empty
- **THEN** `ValidateParams` returns an error that names the empty key

## MODIFIED Requirements

### Requirement: Instance open versus subscribe validation
`ValidateParams` SHALL enforce the open-vs-subscribe matrix for each leg (LAPI, AppSec, and captcha). When `bouncerEnabled` is false and the leg enable flag is false, a non-empty instance name, API key, or client certificate for that leg SHALL fail validation (E2). Captcha E2 is a leftover `captchaInstanceName` (not leftover `bouncerCaptcha*` keys). When `bouncerEnabled` is true, the leg enable flag is false, and the instance name is omitted after prepopulation rules, the bouncer SHALL NOT subscribe and validation SHALL succeed without treating the leg as open (E3). When a LAPI or AppSec enable flag is true and neither API key nor client certificate can build that client, `ValidateParams` or subsequent `Open` failure SHALL fail `New` for that middleware. When `captchaEnabled` is true, owner-style captcha checks SHALL fail `New` if provider, keys, gate secret, or template cannot build the client.

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
The configuration package SHALL include unit tests covering: custom captcha provider missing fields; AppSec failure action `captcha` without a captcha instance name; **LAPI disabled AppSec-only path (replaces appsec mode without LAPI key)**; alone mode captcha/template failures; `GetTemplate` error paths; `validateURL` bad host; `BouncerRemediationStatusCode` bounds 99/600; `LapiUpdateMaxFailure: -1` acceptance; **instance name E2/E3 cases including captcha**.

#### Scenario: AppSec captcha without instance name rejected
- **WHEN** `bouncerAppsecFailureAction` is `captcha` and `captchaInstanceName` is empty after owner-fill rules
- **THEN** `ValidateParams` returns an error

### Requirement: Alone mode validates captcha templates and logging
In `lapiMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when `captchaEnabled` is true, the captcha template when `captchaEnabled` is true (empty `BouncerCaptchaFilePath` or a `GetTemplate` failure SHALL fail), the ban template when that path is set, and log level / writable log file path. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation. Empty site or secret after file-then-field lookup SHALL fail even when `BouncerCaptchaGateSecret` is set. When `appsecEnabled` is true, it SHALL still validate AppSec URL, AppSec key, and AppSec HTTPS CA.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, `captchaEnabled` is true, failure action is `captcha`, provider is set, `BouncerCaptchaGateSecret` is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error that names `BouncerCaptchaSiteKey` cannot be empty

#### Scenario: Alone mode invalid log level
- **WHEN** mode is `alone` and log level is not one of DEBUG/INFO/WARN/ERROR
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode empty captcha path
- **WHEN** mode is `alone`, `captchaEnabled` is true, provider is set, site, secret, and gate resolve non-empty, and `BouncerCaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `BouncerCaptchaFilePath: cannot be empty when BouncerCaptchaProvider is set`

### Requirement: Reject empty captcha site and secret after lookup
When `captchaEnabled` is true, `ValidateParams` SHALL resolve `BouncerCaptchaSiteKey` and `BouncerCaptchaSecretKey` with the same file-then-field lookup used for `BouncerCaptchaGateSecret`. After a successful lookup it SHALL reject an empty trimmed string for each field independently, site first. The trigger is `captchaEnabled`, not a leftover provider on a subscriber and not a captcha failure action. Error text SHALL be `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set` and `BouncerCaptchaSecretKey: cannot be empty when BouncerCaptchaProvider is set`. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty site and secret
- **WHEN** `captchaEnabled` is true, `bouncerCaptchaProvider` is set, `BouncerCaptchaGateSecret` is set, and both site and secret resolve empty
- **THEN** `ValidateParams` returns `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Only site empty
- **WHEN** `captchaEnabled` is true, `bouncerCaptchaProvider` is set, secret is non-empty, and site resolves empty
- **THEN** `ValidateParams` returns `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Only secret empty
- **WHEN** `captchaEnabled` is true, `bouncerCaptchaProvider` is set, site is non-empty, and secret resolves empty
- **THEN** `ValidateParams` returns `BouncerCaptchaSecretKey: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Whitespace-only site is empty
- **WHEN** `captchaEnabled` is true, `bouncerCaptchaProvider` is set, and site is only whitespace
- **THEN** `ValidateParams` returns `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Default ban action still rejects empty keys
- **WHEN** `captchaEnabled` is true, `bouncerCaptchaProvider` is set, failure actions are the default `ban`, and site/secret resolve empty
- **THEN** `ValidateParams` returns an error that names the empty site key

#### Scenario: New returns no handler
- **WHEN** `New` is called with `captchaEnabled` true, `bouncerCaptchaProvider` set, `BouncerCaptchaGateSecret` set, and empty site key
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI

#### Scenario: Subscriber leftover provider does not require keys
- **WHEN** `captchaEnabled` is false and leftover `bouncerCaptchaProvider` is set with empty site and secret
- **THEN** `ValidateParams` does not fail from this rule

### Requirement: Provider set requires a loadable captcha template
When `captchaEnabled` is true, `ValidateParams` SHALL reject an empty `BouncerCaptchaFilePath` and SHALL fail when `GetTemplate` fails for that path. The trigger is `captchaEnabled`, the same as site, secret, and gate. Error text for the empty path SHALL be `BouncerCaptchaFilePath: cannot be empty when BouncerCaptchaProvider is set`. A `GetTemplate` failure SHALL be returned as that error. Ban template validation SHALL stay "when path is set". `Client.New` SHALL return the `GetTemplate` error and MUST NOT discard it. The plugin MUST NOT invent a bundled default captcha template. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty captcha path
- **WHEN** `captchaEnabled` is true, `bouncerCaptchaProvider` is set, site, secret, and gate resolve non-empty, and `BouncerCaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `BouncerCaptchaFilePath: cannot be empty when BouncerCaptchaProvider is set`

#### Scenario: Provider set with unreadable captcha path
- **WHEN** `captchaEnabled` is true, `bouncerCaptchaProvider` is set, and `BouncerCaptchaFilePath` names a missing or unparseable file
- **THEN** `ValidateParams` returns a `GetTemplate` error

#### Scenario: Empty ban path still accepted
- **WHEN** `captchaEnabled` is true, `bouncerCaptchaProvider` is set, captcha path is loadable, and `BouncerBanFilePath` is empty
- **THEN** `ValidateParams` returns no error from the ban template

#### Scenario: Client.New returns GetTemplate error
- **WHEN** `Client.New` is called with a non-empty provider and an empty or unreadable captcha template path
- **THEN** `Client.New` returns the `GetTemplate` error
- **AND** it does not return nil with a discarded error

#### Scenario: New returns no handler on empty captcha path
- **WHEN** `New` is called with `captchaEnabled` true, `bouncerCaptchaProvider` set, site, secret, and gate set, and empty `BouncerCaptchaFilePath`
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI

### Requirement: Public Config keys use domain prefixes
`Config` SHALL expose flat public JSON keys whose first syllable is the piece that reads them (`lapi`, `appsec`, `bouncer`, `captcha`). Own-axis captcha keys SHALL be `captchaEnabled` and `captchaInstanceName`. Owner-read captcha settings SHALL stay `bouncerCaptcha*`. Logging keys (`logLevel`, `logFormat`, `logFilePath`) and `reclaimGraceSeconds` SHALL stay unprefixed. The plugin MUST NOT accept old `crowdsec*` keys or unprefixed router knobs as aliases, and MUST NOT nest those maps. `GetVariable` lookup strings SHALL be the new Go field names (`LapiKey`, `LapiTLSClientCertificate`, `AppsecKey`, `BouncerCaptchaSiteKey`). TLS prefix helpers SHALL be `Lapi` / `Appsec` plus `TLSCertificateAuthority`, `TLSClientCertificate`, and `TLSClientKey`. Validation errors SHALL name the new Go field.

#### Scenario: Old crowdsec key is ignored
- **WHEN** operator YAML sets only `crowdsecLapiHost` and omits `lapiHost`
- **THEN** Traefik decode leaves `LapiHost` at the CreateConfig default
- **AND** the old key is not a field on `Config`

#### Scenario: GetVariable uses the new field name
- **WHEN** `GetVariable` is called with `LapiKey` and `LapiKeyFile` names a readable file
- **THEN** the lookup returns that file’s trimmed contents
- **AND** a call with `CrowdsecLapiKey` does not resolve `LapiKeyFile`

#### Scenario: Captcha own-axis keys are captcha-prefixed
- **WHEN** the operator sets `captchaEnabled` and `captchaInstanceName`
- **THEN** those keys decode onto `CaptchaEnabled` and `CaptchaInstanceName`
- **AND** owner settings remain `bouncerCaptcha*`
