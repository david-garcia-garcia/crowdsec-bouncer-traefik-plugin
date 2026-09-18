## 1. ValidateParams gate

- [ ] 1.1 Wrap `GetVariable(config, "RedisCachePassword")` in `if config.RedisCacheEnabled` in `ValidateParams`. Do not change `GetVariable`. Do not touch `lapi.Prepare`.

## 2. Regression test

- [ ] 2.1 Add `Test_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled` in `pkg/configuration/zzz_configuration_test.go`
- [ ] 2.2 Disabled Redis + missing file path: `ValidateParams` accepts
- [ ] 2.3 Disabled Redis + directory or unreadable path: `ValidateParams` accepts
- [ ] 2.4 Enabled Redis + missing file path: `ValidateParams` rejects

## 3. Verify

- [ ] 3.1 `go test ./pkg/configuration/ -count=1`
- [ ] 3.2 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`
