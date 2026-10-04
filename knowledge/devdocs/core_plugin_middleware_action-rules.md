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
- After trusted-IP, call `ActionSet.Fold` once. Any ban → `handleRemediationServeHTTP` ban with `lapi.OriginPluginRules(match.BanName)` and return. Pass that match into `serveLAPI` and `serveAppSec`.
- `serveLAPI` returns false when LAPI does not write the response (skip LAPI, no subscription, clean miss, passthrough). `serveAppSec` then runs. A captcha rule queries AppSec first, then serves the plugin gate. Skip AppSec skips that query in `serveAppSec`, `appsecThenNextServeHTTP`, and `applyCaptchaRuleServeHTTP`.
- Captcha flag still runs after LAPI when LAPI did not write. LAPI/AppSec ban (including fail-closed) prevails; WARN `ServeHTTP:forcedCaptchaSuperseded` with attrs `ip` and `name` (the captcha rule). Non-empty AppSec challenge does not override the captcha rule; empty challenge body stays dest fail-closed ban.
- Do not put captcha or skip flags on the inbound request (`core_plugin_clientrequest_inbound-request.md`). Do not fold again on the ServeHTTP path. `appsecThenNextServeHTTP` folds for a solved captcha cookie and widget assets, which call it without the match.
- Closed remediation reason is `rules` (prefix-map `plugin:rules:`). Metrics origin is `plugin:rules:<name>`. Do not hash the list into LAPI ownership or AppSec identity.
- Leftover `bouncerAppsecBypassRules` / `bouncerLapiBypassRules` / `bouncerDecisionHeader` YAML never reaches `New`.

## Pattern snippet

```go
match := b.actionRules.Fold(req.Request)
if match.BanName != "" {
	b.handleRemediationServeHTTP(rw, req, decisionscope.BannedValue, lapi.OriginPluginRules(match.BanName))
	return
}
if b.serveLAPI(rw, req, match) {
	return
}
if b.serveAppSec(rw, req, match) {
	return
}
b.next.ServeHTTP(rw, req.Request)
```

## Key files

- `pkg/httprule/action.go` (`ActionRule`, `NewActionSet`, `Fold`)
- `pkg/configuration/configuration.go` (`BouncerActionRules`)
- `pkg/bouncer/bouncer.go` (ServeHTTP)
- `pkg/bouncer/remediation_header.go` (`headerReasonFromOrigin` prefix `plugin:rules:`)
- `pkg/lapi/client_metrics.go` (`OriginPluginRules`)

## Gotchas

- Header match is unanchored RE2 against each value. Write `^b$` and `^c$`. Bare `b` matches `abc`.
- `[captcha]` still lets LAPI or AppSec ban. `[captcha, bypass]` skips both legs then captchas.
- Captcha without a usable client still passes `ValidateParams` and bans at request time with origin `plugin:rules:<name>`.
- Trusted `bouncerClientTrustedIPs` never hit these rules.
