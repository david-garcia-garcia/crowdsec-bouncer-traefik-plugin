# Action rules

## Language

**Action rule**:
One authoring row on `bouncerActionRules`: required unique `name` (no `:`), required `action` token array, plus the same predicates as `httprule.Rule`. All matching rows contribute. Not a trusted-IP skip, not CrowdSec identity, not the outgoing remediation header.
_Avoid_: first-match-wins, `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, `bouncerDecisionHeader`

## Overview

Compile `bouncerActionRules` once into `*httprule.ActionSet`. After trusted-IP, fold every match: any ban remediates immediately; otherwise OR skipLapi, skipAppsec, skipModsec, and captchaFlag, and name the first bypassCaptcha row. Captcha is not an early return. Express the old header as anchored `^b$` / `^c$` header rules.

## How to use

- Store `BouncerActionRules` on Config. Default `[]`. Compile with `httprule.NewActionSet` in `ValidateParams` (wrap `BouncerActionRules: %w`, discard) and again in `bouncer.New` (store). Do not compile on the request path.
- Tokens: `ban`, `bypass`, `bypassLapi`, `bypassAppsec`, `bypassModsec`, `bypassCaptcha`, `bypassRateLimit`, `captcha`. Array order does not matter. `bypass` sets skipLapi, skipAppsec, and skipModsec, not skipRateLimit. `bypassModsec` skips only ModSec. `bypassRateLimit` skips only the rate limit (`core_plugin_ratelimit.md`). `ban` must be the only token on that row. `captcha` and `bypassCaptcha` cannot share a row.
- `bypassCaptcha` skips no leg. It means this request gets no captcha from this router. Ask `b.bypassesCaptcha(req, match)` in a function that would serve the captcha gate and return `false` (nothing written, the caller continues), as `remediateUnderActionRules`, `captchaAppsecFailure`, `serveAppsecCaptchaGate` and the ModSec failure action `captcha` do. Do not call `handleCaptchaKindServeHTTP` or `handleRemediationServeHTTP` with a captcha kind from a new path without asking it first. `Fold` already cleared `CaptchaName`, so no captcha rule runs and an AppSec `challenge` page is still relayed.
- `appliedLAPIRemediation` takes the match: on a bypassCaptcha request a stored ban that `bouncerOriginBasedDecisionRemap` would soften to a captcha stays a ban.
- After trusted-IP, call `foldActionRules` once (it wraps `ActionSet.Fold`). It clears `SkipAppsec` under `/crowdsec-internal/challenge/` (`isCrowdsecChallengeCallbackPath`) so the challenge stays solvable; LAPI and ModSec skips stay. `Fold` already dropped the skips of a path rule on an ambiguous path (`httprule.SingleReadingPath`). Both log TRACE only (`challengePathKeepsAppsec`, `ambiguousPathRule`). Any ban → `handleRemediationServeHTTP` ban with `lapi.OriginPluginRules(match.BanName)` and return. Pass that match into `serveLAPI`, `serveRateLimit`, `serveAppSec`, and `serveModSec`.
- `serveLAPI` returns false when LAPI does not write the response (skip LAPI, no subscription, clean miss, passthrough, cleared captcha gate, widget asset, bypassed captcha). `serveRateLimit` then runs with the same match (skipped by `SkipRateLimit`), then `serveAppSec`. `serveModSec` runs after AppSec. A captcha rule queries AppSec first, then serves the plugin gate. Skip AppSec skips that query in `serveAppSec` and `applyCaptchaRuleServeHTTP`. Skip ModSec skips inspect in `serveModSec` (`core_plugin_modsecurity_inspect.md`).
- Captcha flag still runs after LAPI when LAPI did not write. LAPI/AppSec ban (including fail-closed) prevails; WARN `warnCaptchaSuperseded` with attrs `ip` and `name` (the captcha rule). Non-empty AppSec challenge does not override the captcha rule; empty challenge body stays dest fail-closed ban.
- Do not put captcha or skip flags on the inbound request (`core_plugin_clientrequest_inbound-request.md`). Fold once in `ServeHTTP`. A cleared gate and a widget asset return false from the captcha handler so that same match reaches `serveAppSec`.
- Closed remediation reason is `rules` (prefix-map `plugin:rules:`). Metrics origin is `plugin:rules:<name>`. Do not hash the list into LAPI ownership or AppSec identity.
- Leftover `bouncerAppsecBypassRules` / `bouncerLapiBypassRules` / `bouncerDecisionHeader` YAML never reaches `New`.

## Pattern snippet

```go
match := b.foldActionRules(req)
if match.BanName != "" {
	b.handleRemediationServeHTTP(rw, req, decisionscope.BannedValue, lapi.OriginPluginRules(match.BanName))
	return
}
if b.serveLAPI(rw, req, match) {
	return
}
if b.serveRateLimit(rw, req, match) {
	return
}
if b.serveAppSec(rw, req, match) {
	return
}
if b.serveModSec(rw, req, match) {
	return
}
b.next.ServeHTTP(rw, req.Request)
```

## Key files

- `pkg/httprule/action.go` (`ActionRule`, `NewActionSet`, `Fold`)
- `pkg/configuration/configuration.go` (`BouncerActionRules`)
- `pkg/bouncer/bouncer.go` (`ServeHTTP`, `foldActionRules`)
- `pkg/bouncer/bouncer_serve_modsec.go` (`serveModSec`)
- `pkg/bouncer/bouncer_serve_captcha.go` (`bypassesCaptcha`)
- `pkg/bouncer/remediation_header.go` (`headerReasonFromOrigin` prefix `plugin:rules:`)
- `pkg/lapi/client_metrics.go` (`OriginPluginRules`)

## Gotchas

- Header match is unanchored RE2 against each value. Write `^b$` and `^c$`. Bare `b` matches `abc`.
- `[captcha]` still lets LAPI or AppSec ban. `[captcha, bypass]` skips LAPI, AppSec, and ModSec then captchas. `[bypassModsec]` still runs LAPI and AppSec.
- Captcha without a usable client still passes `ValidateParams` and bans at request time with origin `plugin:rules:<name>`.
- Trusted `bouncerClientTrustedIPs` never hit these rules.
- A bypass rule never skips AppSec on `/crowdsec-internal/challenge/*`, even when written for that prefix.
- `[bypassCaptcha]` comes before the captcha downgrade: a router with no usable captcha client lets the request through instead of banning it, and does not log `crowdsec bouncer captcha unsubscribed`.
- `[bypassCaptcha]` logs TRACE `bypassCaptcha` with `ip` and `name` only. A bypassed captcha sets no remediation header and is not counted as dropped.
- A bypass path rule does not skip on `..;`, `\`, `%xx`, `;`, `*`, empty or dot segments. A `bypassCaptcha` path rule still applies there (`core_plugin_httprule.md`). Ban and captcha path rules still only see the decoded path: `/x/..;/admin` does not match `^/admin` (follow-up).
