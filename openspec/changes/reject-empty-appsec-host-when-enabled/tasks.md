## 1. Validation

- [ ] 1.1 In `validateAppsecURLKeyAndTLS`, when `CrowdsecAppsecEnabled`, reject an empty `CrowdsecAppsecHost` and a constructed AppSec URL whose host is empty after `http.NewRequest` accepts it
- [ ] 1.2 Leave `validateURL` and `validateParamsRequired` unchanged

## 2. Tests

- [ ] 2.1 `ValidateParams`: enabled + empty host returns an error
- [ ] 2.2 `ValidateParams`: disabled + empty host still returns nil

## 3. Verify

- [ ] 3.1 `go test ./pkg/configuration/...`
