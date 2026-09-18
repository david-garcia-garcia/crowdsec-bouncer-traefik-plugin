## 1. ValidateParams gate

- [x] 1.1 Wrap `GetVariable(config, "RedisCachePassword")` in `if config.RedisCacheEnabled` in `ValidateParams`. Do not change `GetVariable`. Do not touch `lapi.Prepare`.

## 2. Regression test

- [x] 2.1 Add `Test_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled` in `pkg/configuration/zzz_configuration_test.go`
- [x] 2.2 Disabled Redis + missing file path: `ValidateParams` accepts
- [x] 2.3 Disabled Redis + directory or unreadable path: `ValidateParams` accepts
- [x] 2.4 Enabled Redis + missing file path: `ValidateParams` rejects

## 3. Verify

- [x] 3.1 `go test ./pkg/configuration/ -count=1`
- [x] 3.2 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`
