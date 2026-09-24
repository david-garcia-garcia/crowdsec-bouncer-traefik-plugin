## MODIFIED Requirements

### Requirement: Reject empty captcha site and secret after lookup
When `captchaEnabled` is true, `ValidateParams` SHALL resolve `CaptchaSiteKey` and `CaptchaSecretKey` with the same file-then-field lookup used for `CaptchaGateSecret`. After a successful lookup it SHALL reject an empty trimmed string for the site key. It SHALL reject an empty trimmed secret when `captchaProvider` is not `recaptcha-enterprise`. When `captchaProvider` is `recaptcha-enterprise`, an empty secret SHALL pass. Site is still checked first. The trigger is `captchaEnabled`, not a leftover provider on a subscriber and not a captcha failure action. Error text SHALL be `CaptchaSiteKey: cannot be empty when CaptchaProvider is set` and `CaptchaSecretKey: cannot be empty when CaptchaProvider is set`. A `ValidateParams` failure from this rule SHALL cause `New` to return a nil handler and that error without opening LAPI.

#### Scenario: Provider set with empty site and secret
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, `CaptchaGateSecret` is set, and both site and secret resolve empty
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Only site empty
- **WHEN** `captchaEnabled` is true, `captchaProvider` is set, secret is non-empty, and site resolves empty
- **THEN** `ValidateParams` returns `CaptchaSiteKey: cannot be empty when CaptchaProvider is set`

#### Scenario: Only secret empty
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `hcaptcha`, `recaptcha`, `turnstile`, `custom`, or `eucaptcha`, site is non-empty, and secret resolves empty
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
- **WHEN** `captchaEnabled` is true, the provider is `hcaptcha`, `recaptcha`, `turnstile`, `custom`, or `eucaptcha`, and secret resolves empty
- **THEN** `ValidateParams` returns an error that names the empty secret
