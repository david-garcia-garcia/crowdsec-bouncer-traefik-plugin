## ADDED Requirements

### Requirement: Provider token eucaptcha is accepted
When `captchaEnabled` is true, `ValidateParams` SHALL accept `captchaProvider` value `eucaptcha` in addition to empty, `hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, and `custom`. Enterprise knobs MUST NOT be required when this provider is selected. Shared secret-required rules stay on `core_plugin_middleware_config-validation`.

#### Scenario: eucaptcha is a valid provider
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `eucaptcha`, and site key, secret key, gate secret, and template are set
- **THEN** `ValidateParams` returns no error from the provider allowlist

#### Scenario: eucaptcha does not require enterprise knobs
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `eucaptcha`, site, secret, and gate resolve non-empty, and enterprise knobs are empty
- **THEN** `ValidateParams` returns no error from those knobs

## MODIFIED Requirements

### Requirement: Provider token recaptcha-enterprise is accepted
When `captchaEnabled` is true, `ValidateParams` SHALL accept `captchaProvider` value `recaptcha-enterprise` in addition to empty, `hcaptcha`, `recaptcha`, `turnstile`, `custom`, and `eucaptcha`. The enterprise knobs SHALL be required only when this provider is selected and SHALL be ignored otherwise.

#### Scenario: recaptcha-enterprise is a valid provider
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, and the required enterprise knobs, site key, gate secret, and template are set
- **THEN** `ValidateParams` returns no error from the provider allowlist

#### Scenario: Unknown provider still fails
- **WHEN** `captchaEnabled` is true and `captchaProvider` is a token other than empty, `hcaptcha`, `recaptcha`, `turnstile`, `custom`, `recaptcha-enterprise`, or `eucaptcha`
- **THEN** `ValidateParams` returns an error that names `CaptchaProvider`
