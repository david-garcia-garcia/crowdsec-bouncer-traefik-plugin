## ADDED Requirements

### Requirement: CaptchaCustomValidateBody accepted tokens
`ValidateParams` SHALL trim `CaptchaCustomValidateBody` and accept only `""`, `form`, and `json` (exact lowercase). Any other token SHALL fail for any provider. `json` SHALL fail when `captchaProvider` is not `custom`. Empty or `form` on a built-in provider SHALL pass and be ignored. Error text SHALL name `CaptchaCustomValidateBody`. Unknown-token errors SHALL be `CaptchaCustomValidateBody: must be empty, form, or json`. Built-in-plus-`json` errors SHALL be `CaptchaCustomValidateBody: json is only valid when CaptchaProvider is custom`.

#### Scenario: Custom json accepted
- **WHEN** the provider is `custom`, the four required custom strings are set, and `CaptchaCustomValidateBody` is `json`
- **THEN** `ValidateParams` returns no error

#### Scenario: Custom form or omit accepted
- **WHEN** the provider is `custom`, the four required custom strings are set, and `CaptchaCustomValidateBody` is empty or `form`
- **THEN** `ValidateParams` returns no error

#### Scenario: Built-in json rejected
- **WHEN** the provider is hcaptcha, recaptcha, or turnstile and `CaptchaCustomValidateBody` is `json`
- **THEN** `ValidateParams` returns `CaptchaCustomValidateBody: json is only valid when CaptchaProvider is custom`

#### Scenario: Unknown token rejected
- **WHEN** `CaptchaCustomValidateBody` is `JSON`, `Form`, or any other token that is not empty, `form`, or `json` after trim
- **THEN** `ValidateParams` returns `CaptchaCustomValidateBody: must be empty, form, or json`

#### Scenario: Built-in form or omit accepted
- **WHEN** the provider is a built-in and `CaptchaCustomValidateBody` is empty or `form`
- **THEN** `ValidateParams` returns no error

#### Scenario: Whitespace-padded json is json
- **WHEN** the provider is `custom`, the four required custom strings are set, and `CaptchaCustomValidateBody` is ` json `
- **THEN** `ValidateParams` returns no error
