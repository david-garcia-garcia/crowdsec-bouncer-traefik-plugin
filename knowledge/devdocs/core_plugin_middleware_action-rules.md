# Action rules

## Language

**Action rule**:
One authoring row on `bouncerActionRules`: required unique `name` (no `:`), required `action` token array, plus the same predicates as `httprule.Rule`. All matching rows contribute. Not a trusted-IP skip, not CrowdSec identity, not the outgoing remediation header.
_Avoid_: first-match-wins, `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, `bouncerDecisionHeader`

## Overview

Compile `bouncerActionRules` once into `*httprule.ActionSet`. After trusted-IP, fold every match: any ban remediates immediately; otherwise OR skipLapi, skipAppsec, and captchaFlag. Captcha is not an early return. Express the old header as anchored `^b$` / `^c$` header rules.

## How to use

- Store `BouncerActionRules` on Config. Default `[]`. Compile with `httprule.NewActionSet` in `ValidateParams` (wrap `BouncerActionRules: %w`, discard) and again in `bouncer.New` (store). Do not compile on the request path.
- Tokens: `ban`, `bypass`, `bypassLapi`, `bypassAppsec`, `captcha`. Array order does not matter. `bypass` sets skipLapi and skipAppsec. `ban` must be the only token on that row.
- After trusted-IP, call `Matching` then fold. Any ban → `handleRemediationServeHTTP` ban with `lapi.OriginPluginRules(firstBanName)` and return.
- Else OR skipLapi / skipAppsec / captchaFlag. SkipLapi uses `passOrCaptchaRule`. SkipAppsec is checked again in `handleNextServeHTTP` and `applyCaptchaRuleServeHTTP`.
- Captcha flag still runs remaining legs. LAPI/AppSec ban (including fail-closed) prevails; WARN `ServeHTTP:forcedCaptchaSuperseded` with attrs `ip` and `name` (the captcha rule). Non-empty AppSec challenge does not override the captcha rule; empty challenge body stays dest fail-closed ban.
- Do not put captcha or skip flags on `clientRequest`. Recompute `foldActionRules` in helpers.
- Closed remediation reason is `rules` (prefix-map `plugin:rules:`). Metrics origin is `plugin:rules:<name>`. Do not hash the list into LAPI ownership or AppSec identity.
- Leftover `bouncerAppsecBypassRules` / `bouncerLapiBypassRules` / `bouncerDecisionHeader` YAML never reaches `New`.

## Pattern snippet

```go
match := b.foldActionRules(req.Request)
if match.banName != "" {
	b.handleRemediationServeHTTP(rw, req, decisionscope.BannedValue, lapi.OriginPluginRules(match.banName))
	return
}
```

## Key files

- `pkg/httprule/action.go` (`ActionRule`, `NewActionSet`)
- `pkg/configuration/configuration.go` (`BouncerActionRules`)
- `pkg/bouncer/bouncer.go` (`foldActionRules`, ServeHTTP)
- `pkg/bouncer/remediation_header.go` (`headerReasonFromOrigin` prefix `plugin:rules:`)
- `pkg/lapi/client_metrics.go` (`OriginPluginRules`)

## Gotchas

- Header match is unanchored RE2 against each value. Write `^b$` and `^c$`. Bare `b` matches `abc`.
- `[captcha]` still lets LAPI or AppSec ban. `[captcha, bypass]` skips both legs then captchas.
- Captcha without a usable client still passes `ValidateParams` and bans at request time with origin `plugin:rules:<name>`.
- Trusted `bouncerClientTrustedIPs` never hit these rules.
