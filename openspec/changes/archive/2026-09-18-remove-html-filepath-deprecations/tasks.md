## 1. Delete Deprecated fields and New copies

- [x] 1.1 Remove `BanHTMLFilePath` and `CaptchaHTMLFilePath` from `Config` (fields, json tags, comments) in `pkg/configuration/configuration.go`
- [x] 1.2 Delete both `plugin.New` alias blocks so `New` never reads the old keys

## 2. Retarget live leftovers

- [x] 2.1 Set real e2e Traefik labels in `tests/e2e/real/docker-compose.test.yml` to `banFilePath` / `captchaFilePath`
- [x] 2.2 Set mock captcha YAML `tests/e2e/mock/scenarios/captcha/dynamic.yml` to `captchaFilePath`
- [x] 2.3 Retarget README sample and `examples/captcha` / `examples/custom-captcha` HTML-cased keys to `banFilePath` / `captchaFilePath`
- [x] 2.4 Leave `openspec/changes/archive/2026-09-05-add-real-e2e/` unchanged

## 3. Verify

- [x] 3.1 Confirm no remaining product references to `BanHTMLFilePath`, `CaptchaHTMLFilePath`, `banHtmlFilePath`, `captchaHtmlFilePath`, `banHTMLFilePath`, or `captchaHTMLFilePath` outside archive OpenSpec and ticket bus
- [x] 3.2 `go test ./pkg/configuration/ ./` and `golangci-lint run ./pkg/configuration/... .` — do not add an empty-guard alias test
