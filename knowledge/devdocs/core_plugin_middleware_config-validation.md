# Config validation

## Language

**file-then-field lookup**:
Resolution of a Config secret from the matching `*File` path, then the inline field, after trim. It does not read the environment. A successful lookup that trims to empty is the empty string, not a lookup error.
_Avoid_: env lookup, Getenv

**AppsecEnabled**:
The Config field that means this router will open AppSec. Same field `New` uses for `appsec.Open`.
_Avoid_: leftover AppSec host/CA/key, `lapiMode: appsec`, CrowdsecAppsecEnabled

**Config domain prefix**:
The operator label on `configuration.Config` (Go field and JSON tag). It does not travel past the package that owns the value.
_Avoid_: nested YAML, old-key alias, repeating the prefix inside `pkg/lapi` or `pkg/appsec`

**Config validation**:
The `ValidateParams` startup gate `plugin.New` runs on the config snapshot before `lapi.Prepare`.
_Avoid_: `GetVariable` as a feature-flag check

**Writability-check handle**:
The `*os.File` opened only to prove a non-empty `LogFilePath` is writable. Not the process-lifetime logger file.
_Avoid_: sharedLogFiles, reclaim value, log owner

## Overview

`ValidateParams` is `New`'s constructor gate. When it fails, `New` returns a nil handler and that error and does not open LAPI. File-backed secrets go through `GetVariable`, which Stats and reads `<key>File` when that path is non-empty. Gate each `GetVariable` call behind the flag that uses that secret. Captcha site and secret keys are required whenever `bouncerCaptchaProvider` is set, including `lapiMode: alone` and the default `ban` failure action. AppSec URL, key-file, and HTTPS CA run only when `AppsecEnabled` is true. `validateLogging` still `OpenFile`s a non-empty `LogFilePath` even when `logger.NewWithFormat` already holds that path. Close that handle after a successful open.

## How to use

- Run `ValidateParams` on `&config` after the snapshot and before `lapi.Prepare`.
- Keep `LapiHTTPTimeoutSeconds`, `AppsecHTTPTimeoutSeconds`, and `BouncerCaptchaSiteverifyHTTPTimeoutSeconds` in `requiredInt1` (`< 1` invalid). Each knob defaults to 10. Nothing inherits. Do not add `EffectiveHTTPTimeoutSeconds` or three inherit wrappers.
- Resolve `LapiRedisPassword` / `LapiRedisPasswordFile` only when `lapiRedisEnabled` is true.
- When Redis is off, do not Stat or read a leftover `lapiRedisPasswordFile`.
- When Redis is on, keep today's file-error fail. Accept an empty password with an empty file path.
- Do not add an enabled check inside `GetVariable`. Captcha already gates `GetVariable` behind provider-set (`validateEnabledCaptchaSettings`).
- When `BouncerCaptchaProvider` is set, resolve `BouncerCaptchaSiteKey` and `BouncerCaptchaSecretKey` with file-then-field lookup (`GetVariable`). Keep lookup errors.
- After a successful lookup, reject `""` for each field independently, site first.
- Use the same trigger as `BouncerCaptchaGateSecret`: provider set, not "failure action is captcha".
- Error text: `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set` and the secret twin.
- When `BouncerCaptchaProvider` is set, reject an empty `BouncerCaptchaFilePath` (`BouncerCaptchaFilePath: cannot be empty when BouncerCaptchaProvider is set`) and fail when `GetTemplate` fails. Ban template stays "when path is set".
- `captcha.Client.New` returns the `GetTemplate` error. Do not discard it. Do not invent a bundled default template.
- After CAPI (alone) or LAPI (other modes), call `validateAppsecURLKeyAndTLS` only when `config.AppsecEnabled`. Do not hide that `if` only inside a LAPI wrapper — alone never calls it.
- Reuse `AppsecEnabled`. Do not re-derive from leftover AppSec fields or `lapiMode`.
- Reject `lapiMode: appsec` (E4). Gate LAPI URL/keys on `LapiEnabled`. Reject leftover instance name or secret when bounce and owner flags are both false (E2).
- `LapiEnabled` defaults false. Tests and compose that Open LAPI must set it true.
- Keep the helper's empty-key pass and explicit-`https` CA parse. Do not fail an empty AppSec key at `ValidateParams`.
- When the knob is false, skip AppSec host, URL, key, and CA even if leftover fields are set.
- Leave `New` as `return nil, err` on `ValidateParams` failure.
- Trim `BouncerCaptchaCustomValidateBody`. Accept only `""`, `form`, and `json` (exact lowercase). Reject unknown tokens for any provider (`BouncerCaptchaCustomValidateBody: must be empty, form, or json`). Reject `json` when the provider is not `custom` (`BouncerCaptchaCustomValidateBody: json is only valid when BouncerCaptchaProvider is custom`). Built-in leftover `""` / `form` pass and are ignored.
- Keep the `LogFilePath` check as its own `OpenFile` (append/create/write). Do not reuse `sharedLogFiles` and do not skip the open when the logger already opened the path.
- After a successful open, `Close` the writability-check handle. Ignore the `Close` error; writability is already proven.
- Still return an error when the path is not writable. The logger's stdout fallback is a different job.

## Pattern snippet

```go
if config.LapiRedisEnabled {
	if _, err := GetVariable(config, "LapiRedisPassword"); err != nil {
		return err
	}
}
if config.AppsecEnabled {
	if err := validateAppsecURLKeyAndTLS(config); err != nil {
		return err
	}
}
```

```go
siteKey, err := GetVariable(config, "BouncerCaptchaSiteKey")
if err != nil {
	return err
}
if siteKey == "" {
	return errors.New("BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set")
}
```

```go
checkFile, err := os.OpenFile(filepath.Clean(config.LogFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
if err != nil {
	return fmt.Errorf("LogFilePath is not writable %w", err)
}
_ = checkFile.Close()
```

## Key files

- `pkg/configuration/configuration.go` (`ValidateParams`, `validateAppsecURLKeyAndTLS`, `validateCaptchaCredentials`, `GetVariable`, `validateLogging`)
- `plugin.go` (`New` returns `nil, err` before LAPI Open; `appsec.Open` when `AppsecEnabled`; `NewWithFormat` then `ValidateParams`)

## Gotchas

- `GetVariable` Stats a non-empty `*File` path and errors on missing, directory, or unreadable. Empty file path uses the string field, including empty.
- `lapi.Prepare` resolves `LapiRedisPassword` only when `LapiRedisEnabled` is true. When Redis is off, leftover file paths stay out of the reclaim hash.
- Whitespace-only keys and an empty key file are empty after trim.
- Alone still skips LAPI URL/key/TLS after CAPI. Captcha still runs. AppSec helper runs only when `AppsecEnabled`.
- A set provider with default `ban` actions still needs non-empty site and secret.
- A set provider with an empty `BouncerCaptchaFilePath` fails at `ValidateParams`. Tests that used to blank the path to skip `GetTemplate` need a readable fixture.
- Leftover invalid AppSec CA or missing key file boots when AppSec is off (live, stream, none, and alone). `lapiMode: appsec` is rejected.
- Empty AppSec key after a successful lookup still passes; `appsec.Prepare` copies the LAPI key.
- CA parse still triggers on explicit `AppsecScheme == https`, not inherit-https.
- `NewWithFormat` warns and uses stdout when the path is not writable. `ValidateParams` must still fail so `plugin.New` does not start.
- Do not put the writability-check handle on `pkg/reclaim` or add `sync.Once` / a package global for this close. `sharedLogFiles` is the process-lifetime owner.
