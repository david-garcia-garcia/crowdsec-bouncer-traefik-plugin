## 1. Constructor hardening

- [x] 1.1 Propagate `ip.NewChecker` errors from `Bouncer.New`
- [x] 1.2 Propagate `configuration.GetTemplate` ban-template errors from `Bouncer.New`
- [x] 1.3 Initialize captcha in appsec mode when AppSec failure-action captcha is configured

## 2. Tests

- [x] 2.1 Add `pkg/lapi/test_servehttp.go` helper for bouncer ServeHTTP fixtures
- [x] 2.2 Add `pkg/bouncer/servehttp_test.go` covering cache hit, stream unhealthy, redis unreachable, remediation captcha
- [x] 2.3 Replace `TestCaptchaMethodBasedLogic` with `handleRemediationServeHTTP` tests
- [x] 2.4 Add `New` error and appsec captcha-init tests

## 3. Verify

- [x] 3.1 Run `go test ./pkg/bouncer/... ./pkg/lapi/...`
