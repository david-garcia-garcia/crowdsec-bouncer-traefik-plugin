## 1. Stop failing New for templates

- [ ] 1.1 In `pkg/configuration/configuration.go` `validateEnabledCaptchaSettings`, stop returning an error for empty `CaptchaFilePath` or `GetTemplate` failure. Keep site, secret, and gate secret required when a captcha provider is set.
- [ ] 1.2 In `validateCaptchaCredentialsAndTemplates`, stop returning a `GetTemplate` error for a set `BouncerBanFilePath`. Empty ban path stays accepted.

## 2. Owner warnings

- [ ] 2.1 In `pkg/captcha/captcha.go` `Client.New`, when the provider is set and the captcha file is empty or not loadable, emit one WARN `crowdsec captcha template unavailable` with `reason` `empty` or `unloadable`, leave `Valid` false, and return nil. Do not add a second template-missing flag.
- [ ] 2.2 In `pkg/bouncer/bouncer.go` `New`, when the ban file is empty or not loadable, emit one WARN `crowdsec bouncer ban template unavailable` with `reason` `empty` or `unloadable`, keep `banTemplate` nil, and succeed. Do not read `CaptchaFilePath`. Do not warn again on the request path.

## 3. Tests

- [ ] 3.1 Flip `pkg/configuration/zzz_configuration_test.go` `Test_ValidateParams_captchaTemplateRequired` and the alone-mode empty captcha path pin so `ValidateParams` succeeds. Keep empty site/secret/gate failures.
- [ ] 3.2 Flip `pkg/captcha/zzz_siteverify_test.go` `Test_New_returnsGetTemplateError` to assert no error, `Valid` false, and the captcha WARN stem plus `reason`.
- [ ] 3.3 Flip `zzz_plugin_test.go` `TestNew_RejectsEmptyCaptchaFilePath` so `New` returns a handler. Assert captcha WARN once, captcha remediation uses the ban path, and bounce-only leftover `/captcha.html` does not emit the captcha WARN.
- [ ] 3.4 Cover empty and unloadable `BouncerBanFilePath`: `bouncer.New` succeeds, WARN stem plus `reason`, GET ban is status with empty body. Capture logs with `newTestLogSink`.
- [ ] 3.5 Run `go test ./pkg/configuration/ ./pkg/captcha/ ./pkg/bouncer/ . -count=1` for the constructor and template tests this change touches.

## 4. Leave neighbors

- [ ] 4.1 Do not embed `ban.html` or `captcha.html`. Do not change the remediation status code. Do not WARN from `bouncer.New` about `CaptchaFilePath`. Do not write `knowledge/devdocs` this apply.
