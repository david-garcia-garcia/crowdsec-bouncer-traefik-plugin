## Why

`pkg/bouncer` constructor silently skips captcha initialization in appsec mode even when `crowdsecAppsecFailureAction: captcha` is configured, so AppSec failure captcha becomes a ban. `New` also discards trusted-IP and ban-template errors, and the main `ServeHTTP` decision tree lacks direct unit tests.

## What Changes

- Initialize `captchaClient` in appsec mode when AppSec failure-action captcha is configured with a captcha provider.
- Propagate `ip.NewChecker` and `configuration.GetTemplate` errors from `Bouncer.New` (fail closed).
- Add focused `pkg/bouncer` tests for `ServeHTTP`, `handleRemediationServeHTTP`, and `applyLapiFailureAction` captcha paths.
- Add `pkg/lapi` test helper for bouncer-layer ServeHTTP fixtures.
- Replace formula-only `TestCaptchaMethodBasedLogic` with handler tests.

## Capabilities

### New Capabilities

- (none)

### Modified Capabilities

- `core_plugin_appsec_failure-action`: appsec mode SHALL initialize the captcha client when failure-action captcha is configured so `ErrFailureCaptcha` serves captcha, not ban.
- `core_plugin_middleware_instance-reclaim`: `Bouncer.New` SHALL return an error when trusted-IP checker or ban template loading fails after validation.

## Impact

- `pkg/bouncer/bouncer.go`, `pkg/bouncer/bouncer_test.go`, new `pkg/bouncer/servehttp_test.go`
- `pkg/lapi/test_servehttp.go` (test helper only)
