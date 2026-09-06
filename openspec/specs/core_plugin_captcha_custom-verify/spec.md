## Purpose

Governs how this plugin posts a custom captcha provider’s siteverify request so CapJS Standalone JSON verify works without changing Wicketkeeper-style form verify.

## Requirements

### Requirement: CaptchaCustomValidateBody selects custom siteverify encoding
Public config `captchaCustomValidateBody` SHALL be empty, `form`, or `json`. Empty SHALL mean `form`. Unknown values SHALL be rejected at ValidateParams. The field SHALL apply only when `captchaProvider` is `custom`. Built-in `hcaptcha`, `recaptcha`, and `turnstile` SHALL keep urlencoded `secret` and `response` even if this field is set.

#### Scenario: Default is form
- **WHEN** the operator omits `captchaCustomValidateBody` and `captchaProvider` is `custom`
- **THEN** siteverify is `POST` `application/x-www-form-urlencoded` with `secret` and `response`

#### Scenario: JSON body for CapJS
- **WHEN** `captchaProvider` is `custom` and `captchaCustomValidateBody` is `json`
- **THEN** siteverify is `POST` `application/json` with body `{"secret":"<CaptchaSecretKey>","response":"<token>"}`

#### Scenario: Unknown body is invalid
- **WHEN** `captchaCustomValidateBody` is neither empty, `form`, nor `json`
- **THEN** plugin initialization fails validation

#### Scenario: Built-in provider ignores json
- **WHEN** `captchaProvider` is `hcaptcha` and `captchaCustomValidateBody` is `json`
- **THEN** siteverify stays urlencoded `secret` and `response`

### Requirement: Browser token field stays CaptchaCustomResponse
The plugin SHALL read the solved token from the browser POST using `CaptchaCustomResponse` (CapJS default `cap-token`). The outbound siteverify key SHALL remain `response`. The plugin MUST NOT reconstruct the client address for siteverify; grace cache SHALL keep using the `remoteIP` already produced by `pkg/ip.GetRemoteIP`.

#### Scenario: CapJS cap-token maps to response
- **WHEN** `captchaCustomResponse` is `cap-token` and the browser POST includes that field
- **THEN** siteverify sends that value as JSON or form `response`

### Requirement: Validate URL is used as given
`CaptchaCustomValidateURL` SHALL be the full siteverify URL. The plugin MUST NOT insert `CaptchaSiteKey` into that URL.

#### Scenario: CapJS site key in the URL
- **WHEN** `captchaCustomValidateURL` is `https://cap.example/<site_key>/siteverify`
- **THEN** the plugin POSTs to that URL unchanged
