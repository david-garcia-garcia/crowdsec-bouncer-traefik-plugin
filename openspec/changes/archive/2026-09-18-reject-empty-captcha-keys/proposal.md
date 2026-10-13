## Why

`ValidateParams` accepts a set `captchaProvider` when resolved site and secret keys are empty. The baseline spec already requires an error (including alone mode). The existing alone-mode test is a false positive: it fails on a missing gate secret or the default template path, not on empty keys.

## What Changes

- When `captchaProvider` is set, reject empty resolved `CaptchaSiteKey` and `CaptchaSecretKey` after `GetVariable` (file then field, trimmed). Reject each field independently, site first.
- Same trigger as the gate secret: provider set, not “failure action is captcha”. Includes alone mode when `CaptchaGateSecret` is set, and the default `ban` action.
- `New` stays `return nil, err` on `ValidateParams` failure. No handler.
- Grow the existing configuration table and add a `New` validation-fail case. Give provider-present success fixtures dummy site and secret so they still test their own rules.
- **Not BREAKING** for operators who already set both keys. Startups that set a provider without keys will now fail closed.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: reject empty resolved site and secret whenever `captchaProvider` is set; tighten the alone-mode empty-keys scenario so it still errors when the gate secret is set.

## Impact

- `pkg/configuration/configuration.go` (`validateCaptchaCredentials`)
- `pkg/configuration/zzz_configuration_test.go`
- `zzz_plugin_test.go` (`New` validation-fail case)
- `plugin.go` `New` (keep `nil` handler; no code change expected)
