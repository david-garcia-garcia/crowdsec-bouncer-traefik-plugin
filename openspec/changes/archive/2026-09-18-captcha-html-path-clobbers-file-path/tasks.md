## 1. Alias

- [x] 1.1 In `plugin.New`, copy `CaptchaHTMLFilePath` onto `CaptchaFilePath` only when `CaptchaFilePath` is empty (same guard as ban)

## 2. Regression

- [x] 2.1 Add `TestNew_CaptchaFilePathWinsOverDeprecatedHTMLPath` in `zzz_plugin_test.go`; after `New`, serve the challenge and assert the current template body (New snapshots the caller config, so the caller's field cannot prove the alias)
- [x] 2.2 Optional sibling: empty current + non-empty deprecated fills `CaptchaFilePath`

## 3. E2E keys

- [x] 3.1 Point mock `tests/e2e/mock/scenarios/captcha/dynamic.yml` at `captchaFilePath`
- [x] 3.2 Point real `tests/e2e/real/docker-compose.test.yml` captcha label at `captchaFilePath`

## 4. Verify

- [x] 4.1 `go test -run TestNew_CaptchaFilePathWinsOverDeprecatedHTMLPath .`
- [x] 4.2 `go test .` and `go test ./pkg/...`
