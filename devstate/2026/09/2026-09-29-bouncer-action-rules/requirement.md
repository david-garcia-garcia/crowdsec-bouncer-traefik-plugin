# Requirement
IssueKey: 2026-09-29-bouncer-action-rules

Breaking change. Retire public config `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, and `bouncerDecisionHeader`. Replace them with one list, `bouncerActionRules`.

Each rule keeps the existing request predicates (`method`, `path`, `host`, `headers`, `cookies`: omitted means any; set predicates AND; Go RE2 unanchored; method may have a single leading `!`; empty header or cookie pattern means that name is present; header names case-insensitive; cookie names case-sensitive; fully empty predicates still fail `New`, including `method: ".*"` as any). Add:

- `name` — required, unique in the list, must not contain `:`.
- `action` — a required non-empty array. Tokens: `bypass`, `bypassLapi`, `bypassAppsec`, `ban`, `captcha`. Order in the array does not matter. `bypass` is sugar for skipping both LAPI and AppSec. Duplicates, unknown tokens, an empty array, or an omitted action fail `New`. `ban` must be the only token in that array; `ban` combined with `captcha` or any skip fails `New`. The action array is not a match predicate.

All matching rules contribute. This is not first-match-wins. List order only picks the name when two rules share the same winning remediation.

Effects:

- Any matching `ban` → immediate ban. LAPI and AppSec do not run. Metrics origin `plugin:rules:<name>` where `<name>` is the first matching ban rule. `remediation=ban`. A bypass on another matching rule does not weaken this ban.
- Otherwise fold every match: `bypass` or `bypassLapi` skips LAPI; `bypass` or `bypassAppsec` skips AppSec; any `captcha` token sets a soft captcha flag. Skips add; they never cancel each other or a captcha flag.
- `captcha` does not return immediately. Legs that were not skipped still run. An active LAPI ban, or a fail-closed ban from that leg (lookup error, stream/alone unhealthy, failure action `ban`), prevails over the captcha rule. An AppSec `ban` verdict, or an AppSec failure-action `ban`, prevails over the captcha rule. Those drops keep the leg's own origin, not `plugin:rules:`. Log a warning that names the captcha rule that lost (same situation as today's `ServeHTTP:forcedCaptchaSuperseded`).
- An AppSec `challenge` is not a ban and does not override the captcha rule.
- A CrowdSec captcha decision is unchanged: the rule does not replace that outcome, the metrics origin stays the CrowdSec origin, and AppSec for that decision stays where it is today (after a valid captcha gate cookie, not before the challenge page).
- If no leg banned and a captcha rule matched, serve the existing captcha gate. Origin `plugin:rules:<name>` of the first matching captcha rule, `remediation=captcha`, only when that rule is what is applied. A valid gate cookie still passes. After the cookie is valid, AppSec still runs unless a matching `bypass` or `bypassAppsec` skipped it.
- The only way for a captcha rule to avoid a LAPI ban is a matching `bypass` or `bypassLapi` (same rule or another matching rule). The only way to avoid an AppSec ban is a matching `bypass` or `bypassAppsec`. Example: one rule with `action: [captcha, bypass]` skips both legs and then captchas. `[captcha, bypassLapi]` still allows AppSec to ban. `[captcha]` alone allows both legs to ban.
- Captcha with no usable captcha client does not fail `New`. It downgrades to a ban at request time with the existing `crowdsec bouncer captcha unsubscribed` warning. That drop's origin is still `plugin:rules:<name>`, `remediation=ban`.
- Skips do not increment `dropped`. `recordProcessed` still runs.
- Rules run after startup block, `GetRemoteIP` (failure still tech-bans), and the trusted-IP skip. Trusted clients never hit these rules. A failed client-IP parse is not saved by a bypass rule.
- Delete the decision-header helpers (`forcedDecisionKind`, `passOrForcedCaptcha`, `remediateOrForcedCaptcha`, `banOrWarnForcedCaptcha`). Nothing after lookup merges a secret `b` or `c`.
- The old header is expressed as rules. Header match is unanchored RE2 against each value, so the patterns must be anchored (`^b$`, `^c$`), not a bare `b`. `[captcha]` keeps today's "LAPI ban beats header c" outcome. `[captcha, bypassLapi]` is a stronger choice and is not the old header.
- These rules must not enter LAPI ownership keys or AppSec identity keys.
- Compile once off the request path (`ValidateParams` and again in `bouncer.New`, same split as the bypass lists). Do not compile per request.
- Traefik drops unknown keys before the plugin sees them, so leftover `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, and `bouncerDecisionHeader` cannot fail `New` and cannot be warned on. Document that break.

Example:

```yaml
bouncerActionRules:
  - name: healthz
    path: "^/healthz$"
    action: [bypass]
  - name: decision-ban
    headers:
      X-Crowdsec-Decision: "^b$"
    action: [ban]
  - name: decision-captcha
    headers:
      X-Crowdsec-Decision: "^c$"
    action: [captcha]
  - name: challenge-health
    path: "^/healthz$"
    action: [captcha, bypass]
```

## Current (code)

- Public Config has `BouncerAppsecBypassRules` and `BouncerLapiBypassRules` (`[]httprule.Rule`) and `BouncerDecisionHeader` (string, empty = off, exact trimmed `b`/`c`): `pkg/configuration/configuration.go`.
- `configuration.New` defaults both bypass lists to empty slices and `BouncerDecisionHeader` to `""`: `pkg/configuration/configuration.go`.
- `ValidateParams` compiles each bypass list with `httprule.New` and wraps the error with the Go field name; it does not compile or reject `BouncerDecisionHeader` (whitespace does not fail): `pkg/configuration/configuration.go`, `pkg/configuration/zzz_decision_header_test.go`, `pkg/configuration/zzz_configuration_test.go`.
- `bouncer.New` compiles the two lists again into `appsecBypassRules` / `lapiBypassRules` (`*httprule.Set`) and stores trimmed `forcedDecisionHeader`: `pkg/bouncer/bouncer.go`.
- `httprule.Rule` has `method`, `path`, `host`, `headers`, `cookies` only. No `name`, no `action`. `httprule.Set.Match` is OR, first match wins, boolean: `pkg/httprule/rule.go`, `pkg/httprule/set.go`.
- Fully empty predicates (including `method: ".*"` as any) fail `httprule.New`; omitted/empty lists pass and match nothing: `pkg/httprule/set.go`, `pkg/configuration/zzz_configuration_test.go`.
- `ServeHTTP` order: disabled → next; startup-block 503; `GetRemoteIP` (fail → `plugin:tech_getremotefail` ban); unparseable client IP (`plugin:tech_trustipfail` ban); `recordProcessed`; trusted-IP skip (both legs, no rules); then exact header `b` ban (`plugin:forced_decision`); then `lapiBypassRules.Match` → `passOrForcedCaptcha`; else LAPI lookup / failure action. AppSec skip is later in `handleNextServeHTTP`: `pkg/bouncer/bouncer.go`.
- `forcedDecisionKind` uses `Header.Get` (first value) and exact trimmed `b`/`c`, not RE2 and not each value: `pkg/bouncer/bouncer.go`.
- `passOrForcedCaptcha`, `remediateOrForcedCaptcha`, and `banOrWarnForcedCaptcha` merge header `c` after lookup. A LAPI/fail-closed ban wins and logs `ServeHTTP:forcedCaptchaSuperseded` with attr `header`. Forced captcha origin is `plugin:forced_decision`: `pkg/bouncer/bouncer.go`, `pkg/lapi/client_metrics.go`.
- Unsubscribed / unusable captcha kind WARNs `crowdsec bouncer captcha unsubscribed` then bans, keeping the incoming origin: `pkg/bouncer/bouncer.go` `handleCaptchaKindServeHTTP`.
- AppSec `ActionBan` bans with origin `appsec`. AppSec failure-action default bans with `plugin:appsec_failure`. `ActionChallenge` writes the AppSec envelope; empty challenge body still bans (`headerReasonAppsecChallengeEmpty`): `pkg/bouncer/bouncer.go`.
- CrowdSec captcha kind uses the CrowdSec origin, the existing gate, and AppSec only after a valid cookie (`handleCaptchaKindServeHTTP` → `handleNextServeHTTP`): `pkg/bouncer/bouncer.go`.
- Skips do not call `recordDropped`. `recordProcessed` runs before trusted-IP and rules: `pkg/bouncer/bouncer.go`.
- Bypass lists and `BouncerDecisionHeader` are not fields on LAPI `ownership` / `identity` or AppSec `identity`: `pkg/lapi/identity.go`, `pkg/appsec/session.go`.
- Live SHALL rows freeze the two bypass lists (first-match-wins, independent legs, after forced `b`) and forced-decision header `b`/`c`: `openspec/specs/core_plugin_middleware_bouncer/spec.md`, `openspec/specs/core_plugin_middleware_config-validation/spec.md`, `openspec/specs/core_plugin_middleware_forced-decision/spec.md`, `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`.
- README documents `bouncerDecisionHeader` and the two bypass lists. Usage docs name the same three knobs: `README.md`, `knowledge/devdocs/core_plugin_middleware.md`, `knowledge/devdocs/core_plugin_httprule.md`, `knowledge/devdocs/core_plugin_middleware_forced-decision.md`, `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`.
- Tests: `pkg/bouncer/zzz_bypass_rules_test.go`, `pkg/bouncer/zzz_forced_decision_test.go`, `pkg/httprule/zzz_httprule_test.go`, `tests/e2e/mock/scenarios/request-bypass-rules/`.
- `bouncerActionRules`, `plugin:rules:<name>`, and all-matching (not first-wins) contribution: not found.

## Out of scope

- Changing trusted-IP skip, startup-block 503, or `GetRemoteIP` fail-closed ban.
- Changing CrowdSec captcha-decision origin, gate cookie HMAC, or AppSec-after-valid-cookie for a CrowdSec captcha.
- A Traefik-side warning or `New` failure for leftover `bouncerAppsecBypassRules` / `bouncerLapiBypassRules` / `bouncerDecisionHeader` (the spec says Traefik drops those keys).
- Putting action rules into LAPI ownership keys or AppSec identity keys.
- Compiling rules on the request path.
- A converter that rewrites old YAML onto `bouncerActionRules`.
- New captcha providers or a new captcha gate.

## Unknowns

- Whether `name` / `action` land on `httprule.Rule` or a wrapper type beside `pkg/httprule` (ask keeps today's predicates and the ValidateParams / `bouncer.New` compile split).
- Whether `Set.Match` stays first-wins boolean and a new collector folds all hits, or httprule grows a multi-match API.
- Exact `New` / `ValidateParams` error text for missing name, `:`, duplicate names, unknown action tokens, duplicates, empty/omitted action, and `ban` mixed with other tokens.
- WARN attributes when a captcha rule loses (today `ServeHTTP:forcedCaptchaSuperseded` logs `header`; the ask says name the captcha rule that lost).
- Whether an omitted or empty `bouncerActionRules` list is valid and matches nothing (today's empty bypass lists do).
- How AppSec `ActionChallenge` with empty `UserBodyContent` (dest still bans) sits next to "an AppSec `challenge` is not a ban and does not override the captcha rule."

## Tensions

- Ask: one list, all matching rules contribute. Dest: two independent lists, `Set.Match` first-wins, plus a separate force header after trusted-IP and before LAPI bypass (`pkg/httprule/set.go`, `pkg/bouncer/bouncer.go`).
- Ask: delete `forcedDecisionKind` / `passOrForcedCaptcha` / `remediateOrForcedCaptcha` / `banOrWarnForcedCaptcha` and stop merging a secret `b`/`c` after lookup. Dest ServeHTTP and pass-path helpers still do that (`pkg/bouncer/bouncer.go`).
- Ask: header match is unanchored RE2 against each value (`^b$` / `^c$`). Dest force header is `Header.Get` exact trimmed `b`/`c` (`pkg/bouncer/bouncer.go`). A bare `b` pattern would also match `abc`.
- Ask: metrics origin `plugin:rules:<name>`. Dest forced drops use `plugin:forced_decision` (`pkg/lapi/client_metrics.go`, `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`).
- Ask: `[captcha]` keeps "LAPI ban beats header c"; `[captcha, bypassLapi]` is stronger and is not the old header. Dest header `c` plus a LAPI bypass already skips lookup and captchas (`passOrForcedCaptcha` after `lapiBypassRules.Match`).
- Ask: AppSec `challenge` is not a ban and does not override the captcha rule. Dest `ActionChallenge` with empty body still bans (`pkg/bouncer/bouncer.go`).
- Live specs freeze `bouncerAppsecBypassRules` / `bouncerLapiBypassRules` / `bouncerDecisionHeader` (`openspec/specs/core_plugin_middleware_bouncer/spec.md`, `openspec/specs/core_plugin_middleware_forced-decision/spec.md`, `openspec/specs/core_plugin_middleware_config-validation/spec.md`). This ask retires those public keys.
- Traefik unused-key decode means leftover old keys cannot fail `New` (same break as the last list rename). Operators who still send `b`/`c` without rewriting to `bouncerActionRules` lose the force header.
