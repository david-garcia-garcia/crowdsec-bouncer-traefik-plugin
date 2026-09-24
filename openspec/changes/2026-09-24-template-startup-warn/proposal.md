## Why

A bouncing router must start when the captcha page or the ban page cannot be loaded. Dest fails `New` for a missing captcha file and stays silent on an empty ban path. Operators get a dead route instead of a startup warning and the existing ban fallback.

## What Changes

- `ValidateParams` no longer fails `New` for an empty or unloadable captcha template, or for an unloadable ban template. Site key, secret, and gate secret stay required when a captcha provider is set.
- The captcha owner (`Client.New` / `Open`) warns once when the captcha file is empty or not loadable, succeeds, and leaves `Valid` false so the existing ban fallback fires.
- `bouncer.New` warns once when the ban file is empty or not loadable and keeps `banTemplate` nil. Ban responses stay a status with an empty body. HEAD stays bodyless even when a template loads.
- Bounce-only never Opens captcha, so unused default `/captcha.html` is never read and is not warned.
- No bundled default page. No per-request template-missing WARN. No new public config keys.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: captcha and ban templates warn at their owners instead of failing `New`; empty or unloadable ban path warns once; `Client.New` succeeds with `Valid` false.

## Impact

- `pkg/configuration/configuration.go` (`validateEnabledCaptchaSettings`, `validateCaptchaCredentialsAndTemplates`)
- `pkg/captcha/captcha.go` `Client.New`
- `pkg/bouncer/bouncer.go` `New` (ban-file warn only)
- Tests that pin today's hard fail: `zzz_plugin_test.go` `TestNew_RejectsEmptyCaptchaFilePath`, `pkg/configuration/zzz_configuration_test.go` `Test_ValidateParams_captchaTemplateRequired`, `pkg/captcha/zzz_siteverify_test.go` `Test_New_returnsGetTemplateError`
- Live catalog fold only. Neighbors stay as-is: `core_plugin_middleware_captcha-routing` (`!Valid` already bans), `core_plugin_middleware_bouncer` (unpublished / `!Valid` already bans).
- Usage `knowledge/devdocs/core_plugin_middleware_config-validation.md` stays for implement / `opd-devdocsimpact`.
