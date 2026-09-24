## MODIFIED Requirements

### Requirement: Alone mode validates captcha templates and logging
In `lapiMode: alone`, `ValidateParams` SHALL still validate captcha site/secret keys when `captchaEnabled` is true, the captcha template when `captchaEnabled` is true (empty `CaptchaFilePath` or a `GetTemplate` failure SHALL fail), the ban template when that path is set, and log level / writable log file path. It MAY skip LAPI URL, LAPI key, and LAPI TLS checks after CAPI credential validation. Empty site after file-then-field lookup SHALL fail even when `CaptchaGateSecret` is set. Empty secret after lookup SHALL fail when the provider is not `recaptcha-enterprise`, even when `CaptchaGateSecret` is set. When the provider is `recaptcha-enterprise`, empty secret SHALL pass. When `appsecEnabled` is true, it SHALL still validate AppSec URL, AppSec key, and AppSec HTTPS CA.

#### Scenario: Alone mode missing captcha keys
- **WHEN** mode is `alone`, `captchaEnabled` is true, failure action is `captcha`, provider is set, `CaptchaGateSecret` is set, and site/secret keys are empty
- **THEN** `ValidateParams` returns an error that names `CaptchaSiteKey` cannot be empty

#### Scenario: Alone mode invalid log level
- **WHEN** mode is `alone` and log level is not one of DEBUG/INFO/WARN/ERROR
- **THEN** `ValidateParams` returns an error

#### Scenario: Alone mode empty captcha path
- **WHEN** mode is `alone`, `captchaEnabled` is true, provider is set, site, secret, and gate resolve non-empty, and `CaptchaFilePath` is empty
- **THEN** `ValidateParams` returns `CaptchaFilePath: cannot be empty when CaptchaProvider is set`

### Requirement: Instance open versus subscribe validation
`ValidateParams` SHALL enforce the open-vs-subscribe matrix for each leg (LAPI, AppSec, and captcha). When `bouncerEnabled` is false and the leg enable flag is false, a non-empty instance name, API key, or client certificate for that leg SHALL fail validation (E2). Captcha E2 is a leftover `captchaInstanceName` (not leftover owner-read `captcha*` keys). When `bouncerEnabled` is true, the leg enable flag is false, and the instance name is omitted after prepopulation rules, the bouncer SHALL NOT subscribe and validation SHALL succeed without treating the leg as open (E3). When a LAPI or AppSec enable flag is true and neither API key nor client certificate can build that client, `ValidateParams` or subsequent `Open` failure SHALL fail `New` for that middleware. When `captchaEnabled` is true, owner-style captcha checks SHALL fail `New` if provider, keys, gate secret, or template cannot build the client. For `recaptcha-enterprise`, those keys are the site key and the enterprise knobs, not `CaptchaSecretKey`.

#### Scenario: Leftover instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `lapiEnabled` is false, and `lapiInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

#### Scenario: Bouncer with LAPI leg off and no name succeeds
- **WHEN** `bouncerEnabled` is true, `lapiEnabled` is false, AppSec is disabled, and `lapiInstanceName` is omitted
- **THEN** `ValidateParams` returns no error

#### Scenario: Leftover captcha instance name with nothing enabled fails
- **WHEN** `bouncerEnabled` is false, `captchaEnabled` is false, and `captchaInstanceName` is `shared`
- **THEN** `ValidateParams` returns an error

### Requirement: Reject empty captcha site and secret after lookup
When `captchaEnabled` is true, `ValidateParams` SHALL resolve `CaptchaSiteKey` and `CaptchaSecretKey` with the same file-then-field lookup used for `CaptchaGateSecret`. After a successful lookup it SHALL reject an empty trimmed string for the site key. It SHALL reject an empty trimmed secret when `captchaProvider` is not `recaptcha-enterprise`. When `captchaProvider` is `recaptcha-enterprise`, an empty secret SHALL pass. Site is still checked first. The trigger is `captchaEnabled`, not a leftover provider on a subscriber and not a captcha failure action. Error text SHALL be `CaptchaSiteKey: cannot be empty when CaptchaProvider is set` and `CaptchaSecretKey: cannot be empty when CaptchaProvider is set`. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty site and secret
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, `CaptchaGateSecret` is set, and both site and secret resolve empty
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Only site empty
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, secret is non-empty, and site resolves empty
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Only secret empty
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `hcaptcha`, `recaptcha`, `turnstile`, or `custom`, site is non-empty, and secret resolves empty
- **THEN** `ValidateParams` returns `CaptchaSecretKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Enterprise empty secret is accepted
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, site is non-empty, gate is set, required enterprise knobs are set, and secret resolves empty
- **THEN** `ValidateParams` returns no error from the secret

#### Scenario: Whitespace-only site is empty
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, and site is only whitespace
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Default ban action still rejects empty keys
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, failure actions are the default `ban`, and site/secret resolve empty
- **THEN** `ValidateParams` returns an error that names the empty site key

#### Scenario: New returns no handler
- **WHEN** `New` is called with `captchaEnabled` true, `captchaProvider` set, `CaptchaGateSecret` set, and empty site key
- **THEN** `New` returns a nil handler and an error
- **AND** it does not open LAPI

#### Scenario: Subscriber leftover provider does not require keys
- **WHEN** `captchaEnabled` is false and leftover `captchaProvider` is set with empty site and secret
- **THEN** `ValidateParams` does not fail from this rule

### Requirement: Captcha own-axis keys and default
`Config` SHALL expose `captchaEnabled` (Go `CaptchaEnabled`, default false) and `captchaInstanceName` (Go `CaptchaInstanceName`, default empty). `CreateConfig` MUST NOT default `captchaEnabled` true from a set `captchaProvider`. Owner-style captcha checks (provider, site/secret keys, gate secret, loadable template, custom-validate body tokens) SHALL run only when `captchaEnabled` is true. A subscriber leftover owner-read `captcha*` MUST NOT fail those checks. Empty secret SHALL fail those checks only when the provider is not `recaptcha-enterprise`.

#### Scenario: Default is false
- **WHEN** the operator omits `captchaEnabled`
- **THEN** `CreateConfig` leaves it false
- **AND** a set `captchaProvider` does not own captcha

#### Scenario: Subscriber leftover keys do not fail ValidateParams
- **WHEN** `captchaEnabled` is false, `bouncerEnabled` is true, `captchaInstanceName` is `shared`, and leftover `captchaProvider` is set with empty keys
- **THEN** `ValidateParams` returns no error from owner-style captcha checks

#### Scenario: Owner missing keys fail
- **WHEN** `captchaEnabled` is true and site resolves empty
- **THEN** `ValidateParams` returns an error that names the empty key

#### Scenario: Owner missing secret fails except enterprise
- **WHEN** `captchaEnabled` is true, the provider is `hcaptcha`, `recaptcha`, `turnstile`, or `custom`, and secret resolves empty
- **THEN** `ValidateParams` returns an error that names the empty secret
