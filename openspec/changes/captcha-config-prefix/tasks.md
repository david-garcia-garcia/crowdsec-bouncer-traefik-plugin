## 1. Configuration surface

- [ ] 1.1 Rename the seventeen `Config` Go fields `BouncerCaptcha*` → `Captcha*` and JSON tags `bouncerCaptcha*` → `captcha*`. Leave `CaptchaEnabled` / `CaptchaInstanceName` and bounce-decision `Bouncer*` fields. No old-key aliases.
- [ ] 1.2 Reorder `Config` so the new `Captcha*` block sits with `CaptchaEnabled` / `CaptchaInstanceName` (alphabetical by json tag).
- [ ] 1.3 Update `CreateConfig` / `configuration.New` defaults to the new field names (same values: template `/captcha.html`, gate bind true, grace 1800, siteverify timeout 10).
- [ ] 1.4 Update `GetVariable` production strings and `ValidateParams` error text to the new Go names (`CaptchaSiteKey`, `CaptchaSecretKey`, `CaptchaGateSecret`, `CaptchaFilePath`, `CaptchaCustomValidateBody`, `CaptchaProvider`). Leftover owner-read captcha knobs stay non-E2; leftover `captchaInstanceName` stays E2.

## 2. Captcha owner Open

- [ ] 2.1 In `pkg/captcha/session.go` `ownershipFrom` and `newOwnerClient`, read `GetVariable("CaptchaSiteKey"|"CaptchaSecretKey"|"CaptchaGateSecret")` and `cfg.Captcha*` knobs. Keep local parameter names (`siteKey`, `secretKey`, `gateSecret`). Do not grow a `bouncer` field on captcha. Do not reconstruct identity.

## 3. Tests and operator files

- [ ] 3.1 Update unit tests that assign or assert the old names (`pkg/configuration/zzz_*.go`, `pkg/captcha/zzz_owner_test.go`, `pkg/lapi/zzz_session_test.go`, `pkg/bouncer/zzz_http_timeout_test.go`, `zzz_plugin_test.go`, `zzz_constructor_test.go`, `zzz_bouncer_logging_test.go`).
- [ ] 3.2 Rewrite README (BREAKING names the stem move and the pre-prefix `captchaFilePath` revival), `examples/captcha/`, `examples/custom-captcha/`, real compose labels, mock e2e YAML, and `tests/e2e/real/captcha.Tests.ps1` to `captcha*`.
- [ ] 3.3 Leave `knowledge/devdocs` Language/usage folds for implement / `opd-devdocsimpact`. Do not rewrite archived OpenSpec change folders.

## 4. Local verification

- [ ] 4.1 Run the existing configuration and captcha unit tests on this machine and report pass, fail, or not run.
