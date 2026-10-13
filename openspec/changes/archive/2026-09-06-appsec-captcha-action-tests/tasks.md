## 1. AppSec parse test

- [x] 1.1 Add `Test_appsecQuery_captchaJSON` in `pkg/appsec/query_test.go` mirroring `Test_appsecQuery_challengeJSON` with `{"action":"captcha","http_status":403,"user_body_content":"<html>captcha</html>"}`

## 2. Bouncer relay tests

- [x] 2.1 Add `TestHandleNextServeHTTPRelaysStructuredAppsecCaptcha` in `pkg/bouncer/bouncer_test.go` mirroring the challenge relay (status, body, Content-Type, Set-Cookie, X-Remediation=`captcha`)
- [x] 2.2 Add a test that `{"action":"captcha","http_status":403}` with no `user_body_content` relays status 403, empty body, and does not use the operator ban page

## 3. Verify

- [x] 3.1 `go test ./pkg/appsec/ ./pkg/bouncer/ -count=1`
