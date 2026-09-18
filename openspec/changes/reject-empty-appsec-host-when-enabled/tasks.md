## 1. Validation

- [x] 1.1 In `validateAppsecURLKeyAndTLS`, when `CrowdsecAppsecEnabled`, reject an empty `CrowdsecAppsecHost` and a constructed AppSec URL whose host is empty after `http.NewRequest` accepts it
- [x] 1.2 Leave `validateURL` and `validateParamsRequired` unchanged

## 2. Tests

- [x] 2.1 `ValidateParams`: enabled + empty host returns an error
- [x] 2.2 `ValidateParams`: disabled + empty host still returns nil

## 3. Verify

- [x] 3.1 `go test ./pkg/configuration/...`
