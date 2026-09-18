## 1. Alias

- [ ] 1.1 In `plugin.New`, copy `CaptchaHTMLFilePath` onto `CaptchaFilePath` only when `CaptchaFilePath` is empty (same guard as ban)

## 2. Regression

- [ ] 2.1 Add `TestNew_CaptchaFilePathWinsOverDeprecatedHTMLPath` in `zzz_plugin_test.go`; after `New`, assert `config.CaptchaFilePath` equals the current path when both keys are set; keep `CaptchaProvider` empty
- [ ] 2.2 Optional sibling: empty current + non-empty deprecated fills `CaptchaFilePath`

## 3. E2E keys

- [ ] 3.1 Point mock `tests/e2e/mock/scenarios/captcha/dynamic.yml` at `captchaFilePath`
- [ ] 3.2 Point real `tests/e2e/real/docker-compose.test.yml` captcha label at `captchaFilePath`

## 4. Verify

- [ ] 4.1 `go test -run TestNew_CaptchaFilePathWinsOverDeprecatedHTMLPath .`
- [ ] 4.2 `go test .` and `go test ./pkg/...`
