# Captcha enterprise config

## Language

**recaptcha-enterprise**:
The `captchaProvider` token that pairs an enterprise Widget with the assessments Verifier. Not classic `recaptcha`.
_Avoid_: `custom` as a stand-in, sending a migrated classic key to assessments

**Enterprise knobs**:
`captchaEnterpriseKeyType`, `captchaEnterpriseProjectId`, `captchaEnterpriseApiKey` (file twin), `captchaEnterpriseAction`, and `captchaEnterpriseMinScore`. Required only when the provider is `recaptcha-enterprise`.
_Avoid_: requiring them on hCaptcha, classic `recaptcha`, Turnstile, or `custom`

## Overview

`ValidateParams` accepts `recaptcha-enterprise` on the provider allowlist and runs `validateEnterpriseCaptcha` only for that token. Shared site, secret, and gate rules stay on `core_plugin_middleware_config-validation` (empty `CaptchaSecretKey` is allowed only for this provider). Assessments HTTP stays on `core_plugin_middleware_captcha-assessments`.

## How to use

- Allow `captchaProvider` values empty, `hcaptcha`, `recaptcha`, `recaptcha-enterprise`, `turnstile`, and `custom`.
- When the provider is `recaptcha-enterprise`, require `captchaEnterpriseKeyType` `checkbox` or `score`, a non-empty `captchaEnterpriseProjectId` after trim, and a non-empty Cloud API key from `CaptchaEnterpriseAPIKey` / `CaptchaEnterpriseAPIKeyFile` via file-then-field lookup.
- Do not require those knobs on any other provider. Leftover empty enterprise fields on classic `recaptcha` are ignored.
- Checkbox: action and min score MAY be empty after trim (omit `expectedAction` / `data-action` and ignore score).
- Score: require a non-empty action after trim and a `captchaEnterpriseMinScore` that parses as `float64` greater than `0` and at most `1`.
- Keep `captchaEnterpriseMinScore` a string on Config. Zero, negative, `1.1`, and non-numeric fail.

## Pattern snippet

```go
if config.CaptchaProvider == RecaptchaEnterpriseProvider {
	return validateEnterpriseCaptcha(config)
}
```

## Key files

- `pkg/configuration/configuration.go` (`validateCaptcha`, `validateEnterpriseCaptcha`, `validateCaptchaCredentials`)
- `pkg/captcha/session.go` (`ownership`, `newOwnerClient`)
- `pkg/captcha/enterprise.go`

## Gotchas

- `GetVariable` for the API key uses the same file-then-field lookup as other secrets.
- Empty min score after trim is omit and is valid only for checkbox. Score empty fails.
- `CaptchaSecretKey` stays required for hCaptcha, classic `recaptcha`, Turnstile, and `custom`.
