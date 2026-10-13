# Code review
IssueKey: 2026-09-05-add-fail-mode
Fixed point: origin/master (82dc3cedacef220641e7f344c8c0824dea9b1fbe)
Pin: `git diff origin/master...HEAD -- . ':!devstate' ':!.cursor'`

## Standards
1. [hard] Smallest durable delta — `pkg/configuration/configuration.go:159-207` — `New()` re-aligns the entire default `Config` literal while only adding the two failure-action fields and removing the three AppSec block bools
   → Limit edits to the fields this change touches
2. [hard] Smallest durable delta — `pkg/bouncer/bouncer.go:27-73` — `Bouncer` struct and `New()` initializer re-align every field column after replacing three bools with one `appsecFailureAction`
   → Change only the removed/added failure-action fields

## Spec
1. [wrong] `core_plugin_lapi_failure-action` / `core_plugin_appsec_failure-action` — "Empty or unknown values SHALL be rejected." — `validateFailureAction` accepted `""`
2. [wrong] Live LAPI error ban used `ReasonTECH`; spec says same as today’s `BannedValue` path (`ReasonLAPI`)

## Security
none

## Performance
none

## Applied
- Spec 1: reject empty failure-action strings at ValidateParams (`validateFailureAction`); empty YAML now fails; `CreateConfig`/`New()` still default `ban`
- Spec 2: `applyLapiFailureAction` takes `banReason`; live lookup error uses `ReasonLAPI`; stream-unhealthy miss uses `ReasonTECH`

## Recorded and skipped
- Standards 1–2: gofmt realigned composite literals in files this change already edited. Reverting column spacing would fight `gofmt -w`. Not a commandment or usage-Gotcha Do.

Standards: 2 findings, worst: Smallest durable delta restyle in `configuration.go` / `bouncer.go` (skipped)
Spec: 2 findings, worst: empty values accepted; live error reason TECH vs LAPI (applied)
Security: 0 findings, worst: none
Performance: 0 findings, worst: none
