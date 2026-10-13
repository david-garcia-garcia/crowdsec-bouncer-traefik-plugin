# Delivery

## Motivation

Operators cannot compose skip, ban, and captcha on one request matcher. Dest splits that job across two first-match-wins bypass lists (`bouncerLapiBypassRules`, `bouncerAppsecBypassRules`) plus `bouncerDecisionHeader` exact trimmed `b`/`c` that still merges after lookup.

A healthz skip, a header force-ban, and a captcha-without-lookup cannot live on one row. Forced `c` still consults LAPI unless a separate LAPI bypass also matches. Metrics origin for the header path is `plugin:forced_decision`, not a rule name.

Left alone, the two lists and the secret header freeze as the public contract. Operators keep three knobs for one fold, and leftover YAML after a later rename is silent the same way Traefik unused-key decode already drops retired keys.

Priority: P2 — operators cannot compose skip, ban, and captcha on one matcher; leftover old keys are a documented break, not a live outage

## Implementation

One public list `bouncerActionRules` replaces the two bypass lists and the force header. Each row is `httprule.ActionRule` (unique `name`, `action` tokens, embedded predicates). `httprule.NewActionSet` validates names and tokens, then compiles predicates with `httprule.New`. `ValidateParams` wraps `BouncerActionRules: %w` and discards; `bouncer.New` compiles again and stores `*ActionSet`. `Set.Match` stays first-wins boolean; `Matching` returns every hit.

After trusted-IP, `foldActionRules` ORs every match: any `ban` remediates immediately with origin `plugin:rules:<first ban name>` and closed header reason `rules`. Else skip-LAPI / skip-AppSec add, and a `captcha` token is a flag. Remaining legs still run. LAPI or AppSec (including fail-closed) bans keep that leg's origin and WARN `ServeHTTP:forcedCaptchaSuperseded` with `name`. Non-empty AppSec `challenge` does not relay over a captcha rule; empty challenge body stays dest fail-closed ban. Force-header helpers and `plugin:forced_decision` are gone. Leftover old YAML never reaches `New`.

## What this changes

**Operators.** Rewrite `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, and `bouncerDecisionHeader` onto `bouncerActionRules` (unique `name`, `action` tokens, same predicates; write `^b$` / `^c$` for the old header); leftover old keys are ignored.

**Admin users.** None.

**Developers.** Public Config is `BouncerActionRules` (`[]httprule.ActionRule`); applied plugin ban/captcha origin is `plugin:rules:<name>`; closed remediation reason is `rules`; `httprule.Matching` returns every hit.

**End users.** None.
