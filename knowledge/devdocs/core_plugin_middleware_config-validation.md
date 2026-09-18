# Config validation

## Language

**Config validation**:
The `ValidateParams` startup gate `plugin.New` runs on the prepared Config before `lapi.Prepare`.
_Avoid_: `GetVariable` as a feature-flag check

## Overview

Call `ValidateParams` on the prepared Config from `plugin.New` before `lapi.Prepare`. File-backed secrets go through `GetVariable`, which Stats and reads `<key>File` when that path is non-empty. Gate each `GetVariable` call behind the flag that uses that secret.

## How to use

- Run `ValidateParams` on `&prepared` after the snapshot and before `lapi.Prepare`.
- Resolve `RedisCachePassword` / `RedisCachePasswordFile` only when `redisCacheEnabled` is true.
- When Redis is off, do not Stat or read a leftover `redisCachePasswordFile`.
- When Redis is on, keep today's file-error fail. Accept an empty password with an empty file path.
- Do not add an enabled check inside `GetVariable`. Captcha already gates `GetVariable` behind provider-set (`validateEnabledCaptchaSettings`).

## Pattern snippet

```go
if config.RedisCacheEnabled {
	if _, err := GetVariable(config, "RedisCachePassword"); err != nil {
		return err
	}
}
```

## Key files

- `pkg/configuration/configuration.go`
- `plugin.go`

## Gotchas

- `GetVariable` Stats a non-empty `*File` path and errors on missing, directory, or unreadable. Empty file path uses the string field, including empty.
- `lapi.Prepare` still calls `GetVariable` for `RedisCachePassword` with no `RedisCacheEnabled` guard. The error is discarded; a leftover readable file can still load into the reclaim hash.
