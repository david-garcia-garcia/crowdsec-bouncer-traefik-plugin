## 1. ValidateParams alone branch

- [ ] 1.1 After CAPI `GetVariable` on machine id and password, call `validateAppsecURLKeyAndTLS` only
- [ ] 1.2 Do not call `validateLapiAndAppsecConnection` or `validateLapiURLAndKeys` in the alone branch
- [ ] 1.3 Do not add an enabled-or-fields predicate

## 2. Tests

- [ ] 2.1 Add `Test_ValidateParams` row: alone + CAPI + AppSec `https` + garbage CA → error
- [ ] 2.2 Add `Test_ValidateParams` row: alone + CAPI + missing `CrowdsecAppsecKeyFile` → error
- [ ] 2.3 Keep existing "Alone mode with CAPI credentials" row passing (no error)

## 3. Spec

- [ ] 3.1 Apply the `core_plugin_middleware_config-validation` delta (alone AppSec SHALL + test-coverage rows)

## 4. Verify

- [ ] 4.1 `go test ./pkg/configuration/ -count=1`
- [ ] 4.2 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`
