# Config validation

## Language

**file-then-field lookup**:
Resolution of a Config secret from the matching `*File` path, then the inline field, after trim. It does not read the environment. A successful lookup that trims to empty is the empty string, not a lookup error.
_Avoid_: env lookup, Getenv

**CrowdsecAppsecEnabled**:
The Config field that means this router will open AppSec. Same field `New` uses for `appsec.Open`.
_Avoid_: leftover AppSec host/CA/key, `crowdsecMode: appsec`

## Overview

`ValidateParams` is `New`'s constructor gate. When it fails, `New` returns a nil handler and that error and does not open LAPI. Captcha site and secret keys are required whenever `captchaProvider` is set, including `crowdsecMode: alone` and the default `ban` failure action. AppSec URL, key-file, and HTTPS CA run only when `CrowdsecAppsecEnabled` is true.

## How to use

- When `CaptchaProvider` is set, resolve `CaptchaSiteKey` and `CaptchaSecretKey` with file-then-field lookup (`GetVariable`). Keep lookup errors.
- After a successful lookup, reject `""` for each field independently, site first.
- Use the same trigger as `CaptchaGateSecret`: provider set, not "failure action is captcha".
- Error text: `CaptchaSiteKey: cannot be empty when CaptchaProvider is set` and the secret twin.
- After CAPI (alone) or LAPI (other modes), call `validateAppsecURLKeyAndTLS` only when `config.CrowdsecAppsecEnabled`. Do not hide that `if` only inside a LAPI wrapper — alone never calls it.
- Reuse `CrowdsecAppsecEnabled`. Do not re-derive from leftover AppSec fields or `crowdsecMode: appsec`.
- Keep the helper's empty-key pass and explicit-`https` CA parse. Do not fail an empty AppSec key at `ValidateParams`.
- When the knob is false, skip AppSec host, URL, key, and CA even if leftover fields are set.
- Leave `New` as `return nil, err` on `ValidateParams` failure.

## Pattern snippet

```go
if config.CrowdsecAppsecEnabled {
	if err := validateAppsecURLKeyAndTLS(config); err != nil {
		return err
	}
}
```

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

- `pkg/configuration/configuration.go` (`ValidateParams`, `validateAppsecURLKeyAndTLS`, `validateCaptchaCredentials`, `GetVariable`)
- `plugin.go` (`New` returns `nil, err` before LAPI Open; `appsec.Open` when `CrowdsecAppsecEnabled`)

## Gotchas

- Whitespace-only keys and an empty key file are empty after trim.
- Alone still skips LAPI URL/key/TLS after CAPI. Captcha still runs. AppSec helper runs only when `CrowdsecAppsecEnabled`.
- A set provider with default `ban` actions still needs non-empty site and secret.
- Leftover invalid AppSec CA or missing key file boots when AppSec is off (live, stream, none, appsec, and alone).
- Empty AppSec key after a successful lookup still passes; `appsec.Prepare` copies the LAPI key.
- CA parse still triggers on explicit `CrowdsecAppsecScheme == https`, not inherit-https.
