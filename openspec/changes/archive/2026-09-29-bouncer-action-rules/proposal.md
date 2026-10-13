## Why

Operators cannot compose skip, ban, and captcha on one request matcher. Dest splits that job across two first-match-wins bypass lists plus a secret `b`/`c` header that still merges after lookup. One list that folds every match replaces those three knobs before the bypass lists freeze.

## What Changes

- **BREAKING.** Delete public Config `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, and `bouncerDecisionHeader`. No alias, no YAML converter. Traefik unused-key decode drops leftovers; they never reach `New` and cannot be warned on.
- One public list `bouncerActionRules`. Each row keeps today's httprule predicates plus required unique `name` (no `:`) and required `action` token list (`bypass`, `bypassLapi`, `bypassAppsec`, `ban`, `captcha`). All matching rules contribute. List order only picks the origin name when two rules share the same winning remediation.
- Any matching `ban` remediates immediately (`plugin:rules:<name>`, `remediation=ban`). Other matching skips do not weaken it. Else OR skip-LAPI, skip-AppSec, and a captcha flag. Skips do not `recordDropped`; `recordProcessed` stays where dest puts it.
- A captcha token is not an early return. Remaining legs still run. LAPI/AppSec/fail-closed bans keep that leg's origin and WARN `ServeHTTP:forcedCaptchaSuperseded` with `name` of the captcha rule that lost. AppSec Query runs before the plugin captcha gate when AppSec was not skipped. Non-empty AppSec `challenge` does not override the captcha rule; empty challenge body stays dest fail-closed ban.
- Delete `forcedDecisionKind`, `passOrForcedCaptcha`, `remediateOrForcedCaptcha`, and `banOrWarnForcedCaptcha`. Nothing after lookup merges a secret `b` or `c`. Express the old header as rules with anchored `^b$` / `^c$`.
- Closed remediation-header reason `rules` (no third field) replaces `decision-header`. Metrics origin `plugin:rules:<name>` replaces `plugin:forced_decision` on this path.
- Rules stay off LAPI ownership and AppSec identity. Compile once off the request path (`ValidateParams` discards; `bouncer.New` stores).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: one `bouncerActionRules` list replaces the two bypass lists and the force header; all matches fold; `plugin:rules:<name>`; closed reason `rules`.
- `core_plugin_middleware_config-validation`: `ValidateParams` compiles `BouncerActionRules` (name/action plus predicates); empty list passes; leftover old keys are not fields.
- `core_plugin_middleware_forced-decision`: REMOVED. The named capability goes away; remaining behavior is action rules on the bouncer leaf.
- `core_plugin_lapi_usage-metrics`: applied plugin ban/captcha from a rule uses `origin=plugin:rules:<name>`; `plugin:forced_decision` leaves this path.

## Impact

- `pkg/httprule` (wrapper authoring type + `Matching`; `Rule` / `Match` unchanged)
- `pkg/configuration/configuration.go` (delete three knobs; add `BouncerActionRules`; `ValidateParams`)
- `pkg/bouncer/bouncer.go` (compile once; fold after trusted-IP; delete force-header helpers)
- `pkg/bouncer/remediation_header.go` (`headerReasonFromOrigin` prefix `plugin:rules:`)
- `pkg/lapi/client_metrics.go` (origin helper; retire `OriginPluginForcedDecision` on this path)
- Tests: `pkg/bouncer/zzz_bypass_rules_test.go`, `zzz_forced_decision_test.go`, `pkg/httprule`, `pkg/configuration`, `zzz_plugin_test.go`
- Mock e2e: retarget `tests/e2e/mock/scenarios/request-bypass-rules/`
- README; usage `core_plugin_httprule.md`, `core_plugin_middleware.md`, `core_plugin_middleware_forced-decision.md` (unit removed → take the leaf rename), `core_plugin_middleware_config-validation.md`, `core_plugin_lapi_usage-metrics.md`
- Do not change trusted-IP skip, startup-block 503, `GetRemoteIP` fail-closed, CrowdSec captcha-decision origin/gate/AppSec-after-cookie, or reclaim keys
