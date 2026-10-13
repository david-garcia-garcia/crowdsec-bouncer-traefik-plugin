## Purpose

Owns startup validation of the recaptcha-enterprise provider token and its knobs. Shared captcha site, secret, and gate rules stay on `core_plugin_middleware_config-validation`. Assessments HTTP stays on `core_plugin_middleware_captcha-assessments`.

## Requirements

### Requirement: Provider token recaptcha-enterprise is accepted
When `captchaEnabled` is true, `ValidateParams` SHALL accept `captchaProvider` value `recaptcha-enterprise` in addition to empty, `hcaptcha`, `recaptcha`, `turnstile`, `custom`, and `eucaptcha`. The enterprise knobs SHALL be required only when this provider is selected and SHALL be ignored otherwise.

#### Scenario: recaptcha-enterprise is a valid provider
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, and the required enterprise knobs, site key, gate secret, and template are set
- **THEN** `ValidateParams` returns no error from the provider allowlist

#### Scenario: Unknown provider still fails
- **WHEN** `captchaEnabled` is true and `captchaProvider` is a token other than empty, `hcaptcha`, `recaptcha`, `turnstile`, `custom`, `recaptcha-enterprise`, or `eucaptcha`
- **THEN** `ValidateParams` returns an error that names `CaptchaProvider`

### Requirement: Provider token eucaptcha is accepted
When `captchaEnabled` is true, `ValidateParams` SHALL accept `captchaProvider` value `eucaptcha` in addition to empty, `hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, and `custom`. Enterprise knobs MUST NOT be required when this provider is selected. Shared secret-required rules stay on `core_plugin_middleware_config-validation`.

#### Scenario: eucaptcha is a valid provider
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `eucaptcha`, and site key, secret key, gate secret, and template are set
- **THEN** `ValidateParams` returns no error from the provider allowlist

#### Scenario: eucaptcha does not require enterprise knobs
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `eucaptcha`, site, secret, and gate resolve non-empty, and enterprise knobs are empty
- **THEN** `ValidateParams` returns no error from those knobs

### Requirement: Enterprise required knobs when the provider is selected
When `captchaEnabled` is true and `captchaProvider` is `recaptcha-enterprise`, `ValidateParams` SHALL require `captchaEnterpriseKeyType` to be `checkbox` or `score`, a non-empty `captchaEnterpriseProjectId` after trim, and a non-empty Cloud API key from `CaptchaEnterpriseApiKey` or `CaptchaEnterpriseApiKeyFile` via the same file-then-field lookup used for other secrets. Those knobs MUST NOT be required when the provider is not `recaptcha-enterprise`.

#### Scenario: Missing project id fails
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, and `captchaEnterpriseProjectId` is empty
- **THEN** `ValidateParams` returns an error that names `CaptchaEnterpriseProjectId`

#### Scenario: Missing API key fails
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, and the API key resolves empty
- **THEN** `ValidateParams` returns an error that names `CaptchaEnterpriseApiKey`

#### Scenario: Invalid key type fails
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, and `captchaEnterpriseKeyType` is not `checkbox` or `score`
- **THEN** `ValidateParams` returns an error that names `CaptchaEnterpriseKeyType`

#### Scenario: Leftover enterprise knobs on classic recaptcha are ignored
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha`, site, secret, and gate resolve non-empty, and enterprise knobs are empty
- **THEN** `ValidateParams` returns no error from those knobs

### Requirement: Enterprise action and min score by key type
When the key type is `checkbox`, `captchaEnterpriseAction` MAY be empty after trim (omits `data-action` and `expectedAction`) and `captchaEnterpriseMinScore` MAY be empty after trim (ignores `riskAnalysis.score`). When the key type is `score`, `ValidateParams` SHALL require a non-empty action after trim and a `captchaEnterpriseMinScore` that parses as `float64` greater than `0` and at most `1`. `captchaEnterpriseMinScore` SHALL be a string on Config. Zero, negative, `1.1`, and non-numeric values SHALL fail. Empty after trim means omit and is valid only for `checkbox`.

#### Scenario: Score missing action fails
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, key type is `score`, and `captchaEnterpriseAction` is empty
- **THEN** `ValidateParams` returns an error that names `CaptchaEnterpriseAction`

#### Scenario: Score missing min score fails
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, key type is `score`, and `captchaEnterpriseMinScore` is empty
- **THEN** `ValidateParams` returns an error that names `CaptchaEnterpriseMinScore`

#### Scenario: Score zero min score fails
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, key type is `score`, and `captchaEnterpriseMinScore` is `0`
- **THEN** `ValidateParams` returns an error that names `CaptchaEnterpriseMinScore`

#### Scenario: Score 1.1 min score fails
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, key type is `score`, and `captchaEnterpriseMinScore` is `1.1`
- **THEN** `ValidateParams` returns an error that names `CaptchaEnterpriseMinScore`

#### Scenario: Checkbox empty action and min score pass
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, key type is `checkbox`, and action and min score are empty
- **THEN** `ValidateParams` returns no error from those knobs

#### Scenario: Score 1.0 min score passes
- **WHEN** `captchaEnabled` is true, `captchaProvider` is `recaptcha-enterprise`, key type is `score`, action is set, and `captchaEnterpriseMinScore` is `1`
- **THEN** `ValidateParams` returns no error from the min score
