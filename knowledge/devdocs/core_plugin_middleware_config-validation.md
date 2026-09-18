# Config validation

## Language

**file-then-field lookup**:
Resolution of a Config secret from the matching `*File` path, then the inline field, after trim. It does not read the environment. A successful lookup that trims to empty is the empty string, not a lookup error.
_Avoid_: env lookup, Getenv

## Overview

`ValidateParams` is `New`'s constructor gate. When it fails, `New` returns a nil handler and that error and does not open LAPI. Captcha site and secret keys are required whenever `captchaProvider` is set, including `crowdsecMode: alone` and the default `ban` failure action.

## How to use

- When `CaptchaProvider` is set, resolve `CaptchaSiteKey` and `CaptchaSecretKey` with file-then-field lookup (`GetVariable`). Keep lookup errors.
- After a successful lookup, reject `""` for each field independently, site first.
- Use the same trigger as `CaptchaGateSecret`: provider set, not "failure action is captcha".
- Error text: `CaptchaSiteKey: cannot be empty when CaptchaProvider is set` and the secret twin.
- Leave `New` as `return nil, err` on `ValidateParams` failure.

## Pattern snippet

```go
siteKey, err := GetVariable(config, "CaptchaSiteKey")
if err != nil {
	return err
}
if siteKey == "" {
	return errors.New("CaptchaSiteKey: cannot be empty when CaptchaProvider is set")
}
```

## Key files

- `pkg/configuration/configuration.go` (`ValidateParams`, `validateCaptchaCredentials`, `GetVariable`)
- `plugin.go` (`New` returns `nil, err` before LAPI Open)

## Gotchas

- Whitespace-only keys and an empty key file are empty after trim.
- Alone mode still runs this check; it only skips LAPI URL/key/TLS after CAPI lookup.
- A set provider with default `ban` actions still needs non-empty site and secret.
