## 1. Matcher

- [x] 1.1 Add authoring wrapper beside `httprule.Rule` (Name, Action, embedded predicates; flat YAML squash/inline). Do not put `name` / `action` on `Rule`
- [x] 1.2 Add action-list constructor in a sibling httprule file: unique `name` (no `:`, not empty), action token rules (empty/unknown/duplicate/`ban` must be alone), index-prefixed stems from explore, then `httprule.New` on extracted `[]Rule`. Empty list succeeds and matches nothing
- [x] 1.3 Keep `Set.Match` first-wins boolean. Add `Matching(*http.Request) []int` (every matching index in list order; cookie parse once when the set has a cookie predicate)
- [x] 1.4 Tests in `pkg/httprule`: `Match` dest cases still pass; `Matching` returns all hits in order; empty list; wrapper constructor rejects name/action cases and fully empty predicates

## 2. Configuration

- [x] 2.1 Delete `BouncerAppsecBypassRules`, `BouncerLapiBypassRules`, `BouncerDecisionHeader`. Add `BouncerActionRules` (`[]` wrapper type), json `bouncerActionRules`, alphabetical among `Bouncer*`. Default `[]` in `configuration.New`
- [x] 2.2 `ValidateParams` calls the action-list constructor, wraps `BouncerActionRules: %w`, discards the compiled value. Empty list passes. Do not fail because captcha is unusable
- [x] 2.3 Rewrite `pkg/configuration/zzz_configuration_test.go` bypass cases and `zzz_decision_header_test.go` onto `BouncerActionRules` (empty pass; `{}` predicates fail; name/action rejects; method-only/host-only pass; `(` path fails and names the field)

## 3. Bouncer request path

- [x] 3.1 `bouncer.New` compiles `BouncerActionRules` once and stores it. Delete `appsecBypassRules` / `lapiBypassRules` / `forcedDecisionHeader`. Return the constructor error unwrapped. Do not compile on the request path
- [x] 3.2 After trusted-IP, `Matching` then fold: any ban → remediate `plugin:rules:<first ban name>`; else OR skipLapi / skipAppsec / captchaFlag. Delete `forcedDecisionKind`, `passOrForcedCaptcha`, `remediateOrForcedCaptcha`, `banOrWarnForcedCaptcha`
- [x] 3.3 Captcha flag: remaining legs still run. LAPI unless skipped. AppSec Query before the plugin gate unless skipped. Non-empty AppSec challenge does not relay; empty body stays dest fail-closed ban. WARN `ServeHTTP:forcedCaptchaSuperseded` attr `name` (not `header`) plus dest `ip`. CrowdSec captcha-decision path unchanged
- [x] 3.4 `headerReasonFromOrigin` prefix-maps `plugin:rules:` → `rules`. Add `pkg/lapi` origin helper; retire `OriginPluginForcedDecision` when unused
- [x] 3.5 Rewrite `pkg/bouncer/zzz_bypass_rules_test.go` and `zzz_forced_decision_test.go` onto one list (all-matching skips; ban wins over skip; captcha overlay; origins; trusted IP; unanchored header `^b$` vs bare `b`)
- [x] 3.6 Rewrite `zzz_plugin_test.go` constructor rejects onto invalid `BouncerActionRules` (nil handler, no LAPI Open). Confirm `pkg/lapi/identity.go` / `pkg/appsec/session.go` do not hash the list

## 4. Mock e2e

- [x] 4.1 Retarget `tests/e2e/mock/scenarios/request-bypass-rules/` YAML to `bouncerActionRules` (keep folder name). Prove LAPI skip, AppSec skip, independence, and at least one ban or captcha rule

## 5. Docs

- [x] 5.1 README: replace the three knobs with `bouncerActionRules` (predicates; all-matching fold; tokens; `^b$`/`^c$`; leftover old keys ignored)
- [x] 5.2 Usage: `core_plugin_httprule.md` (`Matching`; Config key); `core_plugin_middleware.md` (drop **Bypass rule**, add **Action rule**, request path); `core_plugin_middleware_config-validation.md`; `core_plugin_lapi_usage-metrics.md`. Rename `core_plugin_middleware_forced-decision.md` → `core_plugin_middleware_action-rules.md` (unit removed) and update `index_core_plugin.md` plus references

## 6. Verify

- [x] 6.1 `go test ./pkg/httprule/ ./pkg/configuration/ ./pkg/bouncer/ ./pkg/lapi/ ./pkg/appsec/` and `go test .` plus `golangci-lint run ./pkg/httprule/... ./pkg/configuration/... ./pkg/bouncer/... ./pkg/lapi/...`
- [x] 6.2 `make e2e_mock` (or the harness for `request-bypass-rules`) so the retargeted scenario passes
