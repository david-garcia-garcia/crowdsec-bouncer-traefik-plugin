## Context

See proposal.md Why. Dest compiles two `[]httprule.Rule` lists into `*httprule.Set` (`Match` OR, first match wins, boolean) and stores trimmed `forcedDecisionHeader`. ServeHTTP after trusted-IP: exact `Header.Get` `b`/`c`, then LAPI `Match` → `passOrForcedCaptcha`, AppSec `Match` in `handleNextServeHTTP`. Identity owners (explore): client address stays `pkg/ip.GetRemoteIP` on `clientRequest`; Host match stays httprule `requestHostname`. Traefik unused-key decode drops leftover YAML (`knowledge/research/ext_traefik_plugins_config-decode/`).

## Goals / Non-Goals

**Goals:**
- One compiled action list stored on Bouncer. Predicate compile stays `httprule.New`. Name/action uniqueness and token rules share one constructor `ValidateParams` and `bouncer.New` both call.
- All-matching fold after trusted-IP. Delete force-header helpers. Keep `Set.Match` boolean first-wins for httprule unit tests.
- Prefix-map `plugin:rules:<name>` to closed reason `rules` so colons in the origin never become a third header field.

**Non-Goals:**
- Putting `name` / `action` on `httprule.Rule`.
- Changing `Match` to all-hits.
- A YAML converter or Traefik-side leftover-key warning.
- Hashing the list into LAPI ownership or AppSec identity.
- Compiling on the request path.
- CrowdSec captcha-decision AppSec-after-cookie.

## Decisions

1. Authoring type is a sibling of `httprule.Rule` (Name + Action + embedded predicates, flat YAML via squash/inline so Traefik decode matches the example). `Rule` stays predicates-only. Config field `BouncerActionRules`, json `bouncerActionRules`, alphabetical among `Bouncer*` (first remaining bouncer key after the two lists and header are deleted). Alternative: fields on `Rule` — rejected; Language **Rule** is method/path/host/headers/cookies; second job. Alternative: new package — rejected; configuration and bouncer already import httprule, and a third package would split the compile-once owner.
2. Action-list constructor in httprule (separate file from `Rule`/`Set`): validate name/action (index-prefixed stems from explore), extract `[]Rule`, call `New`, store names/parsed tokens beside `*Set`. `ValidateParams` wraps `BouncerActionRules: %w` and discards. `bouncer.New` compiles again to store. Alternative: validate names in configuration and predicates in httprule — rejected; two owners for one constructor error. Alternative: constructor on `pkg/bouncer` — rejected; `configuration` cannot import `bouncer`.
3. Keep `Set.Match` dest boolean first-wins. Add `Matching(*http.Request) []int` that returns every matching index in list order. Bouncer zips those indices with name/action. Cookie parse once when the set has a cookie predicate, same as `Match`. Alternative: change `Match` to all-hits — rejected; enumerated boolean callers and httprule tests stay. Alternative: fold inside httprule — rejected; httprule does not interpret action tokens on `Match`.
4. Fold after trusted-IP: any ban → `handleRemediationServeHTTP` ban with `plugin:rules:` + first ban name; else OR skipLapi / skipAppsec / captchaFlag. Delete `forcedDecisionKind`, `passOrForcedCaptcha`, `remediateOrForcedCaptcha`, `banOrWarnForcedCaptcha`. When captchaFlag and AppSec not skipped, Query AppSec before the plugin gate; non-empty `ActionChallenge` does not relay; empty body stays dest `headerReasonAppsecChallengeEmpty`. WARN stem stays `ServeHTTP:forcedCaptchaSuperseded`; attr `name` replaces `header`; keep dest `ip`. Alternative: keep merging secret `c` after lookup — rejected; ask deletes those helpers.
5. Origin helper `plugin:rules:` + name in `pkg/lapi` beside the other `OriginPlugin*` constants. Retire `OriginPluginForcedDecision` when no callers remain. `headerReasonFromOrigin` prefix-matches `plugin:rules:` → `rules` (do not exact-match a constant; the name varies; do not fall through to `lapi` plus a third field). Alternative: closed reason that includes the rule name — rejected; colon is the field separator and names MUST NOT contain `:`, but a third field is still the wrong place for a plugin origin.
6. Mock e2e keeps folder `tests/e2e/mock/scenarios/request-bypass-rules/` and retargets YAML to `bouncerActionRules`. Constructor failures stay unit tests. Alternative: rename the scenario folder — rejected; Bound the ask; explore said retarget.

## Risks / Trade-offs

- [Public config break; leftover bypass/header YAML is silent] → README says the keys are gone; Traefik unused-key decode never reaches `New`. No alias.
- [Operators who copy dest `b`/`c` without `^`/`$` also match substrings] → document; header match is unanchored RE2 against each value.
- [Captcha rule without a skip can still be banned by LAPI or AppSec] → that is the commissioned overlay; `[captcha, bypass]` is the stronger choice.
- [Compile twice at New] → one constructor; ValidateParams is the fail-closed gate; Bouncer still owns the stored list.
- [Usage packet `core_plugin_middleware_forced-decision.md` names a removed unit] → take the leaf rename in this change (Issues small/take).

## Migration Plan

**BREAKING.** Operators rewrite the two bypass lists and `bouncerDecisionHeader` onto `bouncerActionRules` (example in requirement.md). Rollback: restore the previous plugin version and the old keys. New binary ignores leftover old keys.

## Open Questions

None — explore rows stand.
