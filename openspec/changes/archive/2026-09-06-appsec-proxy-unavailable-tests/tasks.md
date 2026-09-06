## 1. Unit proof

- [x] 1.1 Add a table-driven test in `pkg/appsec/failure_action_test.go` for AppSec HTTP 502, 503, and 504 × `passthrough` / `ban` / `captcha`, mirroring `Test_appsecQuery_failureActionOn500`
- [x] 1.2 Run `go test ./pkg/appsec/ -count=1` and confirm the new cases pass without product code changes

## 2. Spec delta already written

- [x] 2.1 Confirm the change delta `openspec/changes/appsec-proxy-unavailable-tests/specs/core_plugin_appsec_failure-action/spec.md` still matches the unit table (no extra product requirements)
