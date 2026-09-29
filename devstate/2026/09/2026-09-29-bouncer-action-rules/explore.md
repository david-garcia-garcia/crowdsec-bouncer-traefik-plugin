# Explore
IssueKey: 2026-09-29-bouncer-action-rules

## Concepts

**Action rule** (this change):
One public Config row on `bouncerActionRules`: today's httprule predicates plus required unique `name` and required `action` token list. All matching rules contribute. List order only picks the origin name when two rules share the same winning remediation (first matching `ban`, else first matching `captcha`). Not first-match-wins. Not a trusted-IP skip. Not LAPI ownership or AppSec identity.

**Bypass rule** (dest, retired):
Independent `bouncerLapiBypassRules` / `bouncerAppsecBypassRules` (`[]httprule.Rule`). `Set.Match` OR, first match wins, boolean. LAPI match → `passOrForcedCaptcha`. AppSec match → `next` with no Query.

**Forced decision header** (dest, retired):
`bouncerDecisionHeader` plus `forcedDecisionKind` / `passOrForcedCaptcha` / `remediateOrForcedCaptcha` / `banOrWarnForcedCaptcha`. `Header.Get` first value, exact trimmed `b`/`c`. Origin `plugin:forced_decision`. Header `c` WARN stem `ServeHTTP:forcedCaptchaSuperseded` attr `header`.

Units this change would touch:

| Unit | Path | Job |
| --- | --- | --- |
| Public Config | `pkg/configuration/configuration.go` | Delete the three old knobs; add `BouncerActionRules`; `configuration.New` empty default; `ValidateParams` compile/wrap |
| Matcher | `pkg/httprule` | Keep `Rule` predicates-only; keep `Set.Match` first-wins boolean; add all-match collector; compile-once still `New` |
| Bouncer construct | `pkg/bouncer/bouncer.go` `New` | Compile action list instead of two Sets + trimmed header name |
| Bouncer request path | same file `ServeHTTP` / `handleNextServeHTTP` / `applyAppsecServeHTTP` | Fold matches after trusted-IP; delete force-header helpers; skip legs from folded tokens |
| Metrics origins | `pkg/lapi/client_metrics.go` | Origin `plugin:rules:<name>`; retire `OriginPluginForcedDecision` on this path |
| Remediation header | `pkg/bouncer/remediation_header.go` | Map the new origin to a closed reason token (dest maps `plugin:forced_decision` → `decision-header`) |
| Live catalog | `openspec/specs/core_plugin_middleware_bouncer`, `…_config-validation`, `…_forced-decision`, `core_plugin_lapi_usage-metrics` | Replace bypass + force-header SHALL; new origin |
| Usage | `knowledge/devdocs/core_plugin_httprule.md`, `core_plugin_middleware.md`, `core_plugin_middleware_forced-decision.md`, `core_plugin_middleware_config-validation.md`, `core_plugin_lapi_usage-metrics.md` | Retarget / fold the retired knobs |
| Operator README | `README.md` | Document the break: leftover old keys never reach `New` |
| Tests | `pkg/bouncer/zzz_bypass_rules_test.go`, `zzz_forced_decision_test.go`, `pkg/httprule/zzz_httprule_test.go`, `pkg/configuration/zzz_configuration_test.go`, `zzz_decision_header_test.go`, `zzz_plugin_test.go` | Rewrite onto one list |
| Mock e2e | `tests/e2e/mock/scenarios/request-bypass-rules/` | Retarget to `bouncerActionRules` |

```
ServeHTTP
  disabled → next
  startup-block 503
  GetRemoteIP → recordProcessed; tech-ban on fail (bypass rule cannot save this)
  unparseable client IP → tech-ban
  trusted-IP → next (rules never run)
  Matching() all action rules
       any ban → handleRemediation ban, origin plugin:rules:<first ban name>
                 (LAPI and AppSec do not run)
       else fold skipLapi / skipAppsec / captchaFlag (OR; never cancel)
  if skipLapi → no Lookup / LiveLookup / LAPI failure / stream-unhealthy
  else today's LAPI path
       LAPI ban or fail-closed ban → that origin (not plugin:rules:); WARN if captchaFlag
  if captchaFlag and no ban yet:
       AppSec Query unless skipAppsec (does not return before the remaining leg)
       AppSec ban / failure-action ban → origin appsec / plugin:appsec_failure; WARN if captchaFlag
       AppSec challenge with body → do not override captchaFlag (no relay)
       AppSec challenge empty body → dest ban headerReason appsec-challenge-empty, origin appsec
       else captcha gate, origin plugin:rules:<first captcha name>
            unusable captcha client → dest WARN crowdsec bouncer captcha unsubscribed then ban,
            same plugin:rules origin, remediation=ban
            valid gate cookie → handleNextServeHTTP (AppSec unless skipAppsec)
  pass / no captchaFlag → handleNextServeHTTP (AppSec unless skipAppsec)
```

CrowdSec captcha-decision origin, gate cookie HMAC, and AppSec-after-valid-cookie for that CrowdSec kind stay dest (`Out of scope`).

### Reproduce

Not a failing request. **Confirmed dest** (`go test ./pkg/bouncer/ ./pkg/httprule/ ./pkg/configuration/ -count=1 -timeout 90s -run "ForcedDecision|Bypass|DecisionHeader|httprule"`: ok). Dest force header is `Header.Get` exact `b`/`c` (`forcedDecisionKind`); LAPI bypass is `Set.Match` then `passOrForcedCaptcha`; AppSec bypass is `handleNextServeHTTP` → `next`; empty AppSec challenge body bans (`headerReasonAppsecChallengeEmpty`, origin `appsec`) in `applyAppsecServeHTTP`. `bouncerActionRules` / `plugin:rules:`: not found.

### Call sites (bounded)

Roots searched (worktree, not `vendor/`, not `devstate/`, not `openspec/changes/archive/`): `BouncerAppsecBypassRules|BouncerLapiBypassRules|BouncerDecisionHeader|forcedDecisionKind|passOrForcedCaptcha|remediateOrForcedCaptcha|banOrWarnForcedCaptcha|OriginPluginForcedDecision|func \(set \*Set\) Match|\.Match\(`.

`Set.Match` production: **2** (`pkg/bouncer/bouncer.go` LAPI after trusted-IP; AppSec in `handleNextServeHTTP`). Tests: `pkg/httprule/zzz_httprule_test.go`, `pkg/bouncer/zzz_bypass_rules_test.go`. All migratable here.

Force-header helpers: **one file** `pkg/bouncer/bouncer.go` (definition plus ServeHTTP / pass / remediate / ban-or-warn call sites). Tests: `pkg/bouncer/zzz_forced_decision_test.go`. All migratable here.

`OriginPluginForcedDecision`: `pkg/lapi/client_metrics.go` constant; `headerReasonFromOrigin` in `pkg/bouncer/remediation_header.go`; bouncer force path; metrics + forced-decision tests.

Bypass lists are not on LAPI `ownership` / `identity` (`pkg/lapi/identity.go`) or AppSec `identity` (`pkg/appsec/session.go`). Do not add action rules there (`Out of scope`).

### Outside facts

- Traefik Yaegi mapstructure: unused keys dropped (`knowledge/research/ext_traefik_plugins_config-decode/`). After the three fields are gone, leftover `bouncerAppsecBypassRules` / `bouncerLapiBypassRules` / `bouncerDecisionHeader` YAML cannot fail `New` and cannot be warned on. Same break as the last list rename. In-tree.
- Header match for action rules reuses httprule: unanchored RE2 against each value (`req.Header[canonical]`, not `Header.Get`). Dest force header is first-value exact. Operators who want dest `b`/`c` write `^b$` / `^c$`. In-tree `pkg/httprule/set.go` `oneValueMatches`.
- Nested YAML already decodes (`tests/e2e/mock/scenarios/request-bypass-rules/`). WeaklyTypedInput is the same decoder.

## Decisions

- Chosen: one public list `bouncerActionRules` replaces the two bypass lists and `bouncerDecisionHeader`. No alias, no YAML converter (`Out of scope`). Document the Traefik unused-key break.
- Chosen authoring type: wrapper beside `httprule.Rule` (Name + Action + embedded predicates). Do not put `name` / `action` on `Rule`. httprule stays the compile-once predicate owner (stdlib only).
- Chosen match API: keep `Set.Match` first-wins boolean (httprule unit tests + any remaining boolean ask). Add `Matching(*http.Request) []int` (or equivalent) that returns every matching index in list order. Bouncer zips those indices with name/action. Do not change `Match` to all-hits.
- Chosen compile split: same as dest bypass lists. Predicate compile in `httprule.New`. Name/action uniqueness and token rules in the action-list constructor. `ValidateParams` calls it and wraps with `BouncerActionRules`; discards the compiled value. `bouncer.New` compiles again to store it. Never compile on the request path.
- Chosen fold: after trusted-IP, collect all matches. Any `ban` wins immediately (other matching skips do not weaken it). Else OR the skip tokens and the captcha flag. Skips do not `recordDropped`; `recordProcessed` stays where dest puts it (before trusted-IP and rules).
- Chosen captcha-rule legs: a captcha token is not an early return. Remaining legs still run. LAPI unless `bypass`/`bypassLapi`. AppSec Query unless `bypass`/`bypassAppsec`, including **before** the plugin captcha gate so an AppSec ban can prevail over an unsolved visitor. After a valid gate cookie, dest `handleCaptchaKindServeHTTP` → `handleNextServeHTTP` still runs AppSec unless skipped. CrowdSec captcha-decision path unchanged.
- Chosen AppSec challenge overlay: non-empty `ActionChallenge` is not a ban and does not override a matched captcha rule (do not relay; apply the plugin gate). Empty `UserBodyContent` stays dest fail-closed ban (`headerReasonAppsecChallengeEmpty`, origin `appsec`) and therefore prevails over the captcha rule like `ActionBan`.
- Chosen origin: applied plugin ban/captcha uses `plugin:rules:<name>` of the first matching rule of that winning kind. LAPI/AppSec/fail-closed drops keep that leg's origin. Unusable captcha client on a captcha rule keeps `plugin:rules:<name>` with `remediation=ban` and dest WARN `crowdsec bouncer captcha unsubscribed`.
- Chosen live contract: fold `core_plugin_middleware_bouncer` (request path + lists), `core_plugin_middleware_config-validation` (compile/empty/invalid), `core_plugin_lapi_usage-metrics` (origin). `core_plugin_middleware_forced-decision` is REMOVED (the named capability goes away; remaining behavior is action rules on the bouncer leaf). Usage packet `core_plugin_middleware_forced-decision.md` retargets or folds in the same change (unit removed → take the leaf rename).
- Chosen e2e: retarget mock `tests/e2e/mock/scenarios/request-bypass-rules/`. Constructor failures stay unit tests.
- Rejected: `name`/`action` fields on `httprule.Rule` (second job on the predicate type; `core_plugin_httprule.md` Language **Rule** is method/path/host/headers/cookies).
- Rejected: changing `Set.Match` to all-matching (would reshape the enumerated boolean contract as a means).
- Rejected: keeping `forcedDecisionKind` and merging secret `b`/`c` after lookup (ask deletes those helpers).
- Rejected: a converter or Traefik-side leftover-key warning (`Out of scope`).
- Rejected: hashing action rules into LAPI ownership or AppSec identity (`Out of scope`).
- Rejected: compiling on the request path (`Out of scope`).
- Rejected: first-match-wins for action fold (ask: all matching contribute).
- Live contract: `openspec/specs/core_plugin_middleware_bouncer`, `openspec/specs/core_plugin_middleware_config-validation`, `openspec/specs/core_plugin_middleware_forced-decision`, `openspec/specs/core_plugin_lapi_usage-metrics`.

## Open questions

- Q: Whether `name` / `action` land on `httprule.Rule` or a wrapper type beside `pkg/httprule`?
  Rank: additive asked — new authoring fields this change creates; requirement Add `name` and `action` while keeping today's predicates
  Decision: assumed — wrapper (Name, Action, embedded `httprule.Rule` predicates). `Rule` stays predicates-only. Config slice type carries the wrapper. httprule does not interpret action tokens.
  By: explore

- Q: Whether `Set.Match` stays first-wins boolean and a new collector folds all hits, or httprule grows a multi-match API that replaces `Match`?
  Rank: additive asked — new all-matching fold; Effects All matching rules contribute. This is not first-match-wins. `Match` callers enumerated: 2 production (`pkg/bouncer/bouncer.go`) plus httprule/bouncer tests; roots `pkg/**/*.go` for `func (set *Set) Match` and `.Match(`
  Decision: assumed — keep `Match` as dest boolean first-wins. Add `Matching` that returns every matching index in list order. Bouncer folds name/action from those indices. Do not change `Match`'s contract.
  By: explore

- Q: Exact `New` / `ValidateParams` error text for missing name, `:`, duplicate names, unknown action tokens, duplicates, empty/omitted action, and `ban` mixed with other tokens?
  Rank: additive asked — new constructor rejects; requirement those cases fail `New`
  Decision: assumed — inner stems on the action-list constructor, index-prefixed like dest httprule (`rule %d: …`): `name: empty`, `name: contains colon`, `name: duplicate`, `action: empty`, `action: unknown %q`, `action: duplicate`, `action: ban must be alone`. `ValidateParams` wraps `BouncerActionRules: %w` (same as dest `BouncerLapiBypassRules: %w`). Predicate errors stay httprule's (`empty`, `method:`, `path:`, …). Do not invent a second wrap in `bouncer.New`.
  By: explore

- Q: WARN attributes when a captcha rule loses (today `ServeHTTP:forcedCaptchaSuperseded` logs `header`)?
  Rank: additive asked — same situation as dest WARN; Effects Log a warning that names the captcha rule that lost
  Decision: assumed — keep stem `ServeHTTP:forcedCaptchaSuperseded`. Replace attr `header` with `name` (the first matching captcha rule that lost). Keep dest `ip`. Do not keep `header` (the force header is gone).
  By: explore

- Q: Whether an omitted or empty `bouncerActionRules` list is valid and matches nothing?
  Rank: additive asked — replacement of dest empty bypass lists; requirement Current empty slices pass and match nothing, and the new list replaces those knobs
  Decision: assumed — yes. `configuration.New` defaults `[]`. Omit or empty passes `ValidateParams` / `bouncer.New` and matches nothing (setting off). A list with one fully empty predicate row still fails httprule `New`.
  By: explore

- Q: How AppSec `ActionChallenge` with empty `UserBodyContent` (dest still bans) sits next to "an AppSec `challenge` is not a ban and does not override the captcha rule"?
  Rank: additive asked — captcha-rule overlay on dest `applyAppsecServeHTTP`; Unknowns that sentence; Effects An AppSec `challenge` is not a ban
  Decision: assumed — non-empty challenge does not override a matched captcha rule (no relay; plugin gate). Empty body stays dest fail-closed ban (`headerReasonAppsecChallengeEmpty`, origin `appsec`) and prevails over the captcha rule like `ActionBan`. Do not change empty-challenge dest when no captcha rule matched.
  By: explore

- Q: Who already owns client address and Host for these rules?
  Rank: additive asked — request path after GetRemoteIP / trusted-IP; Effects Rules run after GetRemoteIP and trusted-IP skip; Host is an existing httprule predicate
  Decision: resolved — client address is `pkg/ip.GetRemoteIP` on `clientRequest` (`pkg/bouncer/clientrequest.go`). Trusted-IP skip uses `req.ipAddr`; rules never run for trusted clients. Host match is httprule `requestHostname` (`req.Host`, `net.SplitHostPort` when that succeeds). Do not reconstruct either from a rawer signal. Action rules stay off LAPI ownership and AppSec identity.
  By: explore

- Q: When a captcha rule matched and AppSec is not skipped, does AppSec Query run before the plugin captcha gate?
  Rank: additive asked — new captcha-rule sequencing this change creates; Effects captcha does not return immediately. Legs that were not skipped still run. An AppSec ban prevails over the captcha rule
  Decision: assumed — yes, Query AppSec before serving the plugin captcha gate when AppSec was not skipped, so an AppSec ban can stop an unsolved visitor. After a valid gate cookie, dest AppSec-on-pass still runs unless skipped. Do not change CrowdSec captcha-decision AppSec-after-cookie (`Out of scope`).
  By: explore

- Q: What closed remediation-header reason maps `plugin:rules:<name>`?
  Rank: additive incidental — `headerReasonFromOrigin` already maps plugin origins to closed tokens (`pkg/bouncer/remediation_header.go`); ask names the metrics origin, not the outgoing header
  Decision: assumed — closed reason `rules` (no third field), same pattern as dest `plugin:forced_decision` → `decision-header`. Do not fall through to `lapi` plus a third field (`plugin:rules:…` contains colons). The rule name stays in the metrics origin only. Caller: this is a means to the commissioned origin; no Deviations row (existing mapper, new token this change creates).
  By: explore
