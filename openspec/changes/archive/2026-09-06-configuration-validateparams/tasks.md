## 1. ValidateParams fixes

- [x] 1.1 Add effective AppSec scheme helper and fix AppSec URL validation
- [x] 1.2 Parameterize TLS CA validation for AppSec prefix when AppSec scheme is HTTPS
- [x] 1.3 Restructure alone mode: shared captcha/template/log checks; skip only LAPI block

## 2. Tests

- [x] 2.1 AppSec scheme/TLS validation cases in Test_ValidateParams
- [x] 2.2 Alone mode captcha/template/log cases
- [x] 2.3 AppSec mode without LAPI key; appsec/none mode smoke
- [x] 2.4 Test_validateCaptcha custom provider; AppSec captcha without provider
- [x] 2.5 Test_validateURL, Test_GetTemplate error paths, RemediationStatusCode bounds, UpdateMaxFailure -1

## 3. Verify

- [x] 3.1 Run `go test ./pkg/configuration/...`
