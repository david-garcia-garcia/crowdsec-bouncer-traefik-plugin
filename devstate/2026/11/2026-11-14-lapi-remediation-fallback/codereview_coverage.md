# Test coverage

1. [hard] Edge case untested — `pkg/lapi/client_decisions.go:73` — `deletedTypeClearsStore` names `LapiRemediationFallbackCaptcha` as a case that lets an unknown-type Deleted row clear the slot or CIDR; no test fails if that case is dropped (Deleted tests cover only `ignore` and `ban`)
   Quote:
   ```
   case configuration.LapiRemediationFallbackBan, configuration.LapiRemediationFallbackCaptcha:
       return true
   // TestStreamDeletedUnknownTypeFollowsFallback rows: ignore, ban
   ```
   Fix: Add a `captcha` row to `TestStreamDeletedUnknownTypeFollowsFallback` asserting the Ip and Range bans are cleared
   Status: done
   Argument: Added the `captcha` row (Ip slot and Range CIDR cleared) and updated the test doc comment in `pkg/lapi/zzz_unknown_decision_type_test.go`; `go vet ./...`, `go test ./...`, `golangci-lint run ./...` green.
2. [judgement] Happy path only — `openspec/changes/lapi-remediation-fallback/specs/core_plugin_lapi_origin-based-decision-remap/spec.md:45` — scenario "Unknown type stored as captcha follows captcha edges" has no test that drives ServeHTTP with `lapiRemediationFallback: captcha` and a `captcha: pass` remap
   Fix: Add a Bouncer test with `lapiRemediationFallback: captcha` and `{crowdsec: {captcha: pass}}` asserting no captcha page, or skip with why
   Status: skipped
   Argument: Judgement, not applied unattended. The remap code is unchanged and reads only the stored letter; storing `c` for an unknown type under `captcha` is proven by `TestStreamNewUnknownTypeFollowsFallback`, and `captcha: pass` on a stored `c` by the existing origin-remap tests.
