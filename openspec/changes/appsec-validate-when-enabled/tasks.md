## 1. Validation gate

- [ ] 1.1 In `ValidateParams` alone: after CAPI machine id and password, call `validateAppsecURLKeyAndTLS` only when `config.CrowdsecAppsecEnabled` is true
- [ ] 1.2 In live, stream, none, and appsec: keep LAPI validation; call `validateAppsecURLKeyAndTLS` only when enabled
- [ ] 1.3 Do not hide the gate only inside `validateLapiAndAppsecConnection`; if that wrapper is then a one-liner, inline LAPI then the enabled AppSec call and drop it
- [ ] 1.4 Leave `validateAppsecURLKeyAndTLS` body unchanged (effective-scheme URL, empty-key pass, explicit-`https` CA parse)

## 2. Tests

- [ ] 2.1 Flip `Test_ValidateParams` "AppSec HTTPS with invalid CA while LAPI HTTP" to success (AppSec off leftover CA)
- [ ] 2.2 Set `CrowdsecAppsecEnabled` on the distinct-scheme URL case so it still proves effective scheme
- [ ] 2.3 Add alone + AppSec on + invalid CA / missing key file fail; alone + AppSec off leftover success (CAPI ok)
- [ ] 2.4 Add live or stream + AppSec on + invalid CA / missing key file fail; live or stream + AppSec off leftover success

## 3. Verify

- [ ] 3.1 `go test ./pkg/configuration/` and `golangci-lint run ./pkg/configuration/...`
