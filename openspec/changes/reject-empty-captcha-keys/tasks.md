## 1. Validation

- [ ] 1.1 In `validateCaptchaCredentials`, keep `GetVariable` lookup errors; after each successful lookup reject `""` for site then secret
- [ ] 1.2 Error text: `CaptchaSiteKey: cannot be empty when CaptchaProvider is set` and the secret twin

## 2. Tests

- [ ] 2.1 Give `cfgCaptchaWithProvider` and custom-challenge fixtures dummy site and secret so they stay success cases for their own rules
- [ ] 2.2 Grow `Test_ValidateParams`: empty both (including default `ban`), only site, only secret, whitespace-only site, alone + gate secret + empty keys (assert the site-empty error)
- [ ] 2.3 Add `TestNew_*` in `zzz_plugin_test.go`: provider + gate secret + empty keys → `handler == nil`, `err != nil`; stop before LAPI Open

## 3. Verify

- [ ] 3.1 `go test ./pkg/configuration/ ./` and `golangci-lint run ./pkg/configuration/... .`
