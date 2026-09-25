# Forced decision header

## Language

**Forced decision header**:
The Config string `bouncerDecisionHeader` naming an incoming request header whose exact trimmed values `b` (ban) and `c` (captcha) force that remediation. Ban skips stream/live lookup. Captcha still looks up so an existing ban wins, unless LAPI exclude already skipped that lookup. Empty means the feature is off. Not `bouncerDecisionScopeHeaders` (CrowdSec identity). Not `bouncerRemediationHeadersCustomName` (outgoing).
_Avoid_: BannedValue `t` as a public letter; treating the header as an address or AppSec action; crowdsecDecisionHeader

## Overview

An earlier Traefik middleware can force this bouncer to ban or captcha. ServeHTTP reads the header after the trusted-client skip. `b` remediates without lookup. `c` still consults stream/live lookup so a CrowdSec ban wins (WARN `ServeHTTP:forcedCaptchaSuperseded`), unless `bouncerLapiExcludeRegex` already matched and skipped lookup; then `passOrForcedCaptcha` applies captcha without a store or live check. Otherwise captcha reuses the gate.

## How to use

- Put `bouncerDecisionHeader` on Config. Empty or whitespace is off; do not default a header name.
- Trim the name in `bouncer.New`. Read `Header.Get` after trusted skip, before LAPI exclude and lookup.
- Map public `b` → `BannedValue`, `c` → `CaptchaValue`. Ignore every other token.
- Header `b`: call `handleRemediationServeHTTP` with origin `plugin:forced_decision` and return.
- Header `c`: still look up so a ban wins, unless `bouncerLapiExcludeRegex` already matched this request. On that skip, `passOrForcedCaptcha` applies captcha without store or live lookup. If lookup (or fail-closed ban) is ban, WARN `ServeHTTP:forcedCaptchaSuperseded` and apply that ban. Otherwise captcha with origin `plugin:forced_decision`.
- Do not strip the header.
- Do not put the letter on `clientRequest`. Client address stays `GetRemoteIP`.

## Pattern snippet

```go
if b.forcedDecisionKind(req.Request) == decisionscope.BannedValue {
	b.handleRemediationServeHTTP(rw, req, decisionscope.BannedValue, lapi.OriginPluginForcedDecision)
	return
}
```

## Key files

- `pkg/configuration/configuration.go` (`BouncerDecisionHeader`)
- `pkg/bouncer/bouncer.go` (`forcedDecisionKind`, ServeHTTP)
- `pkg/lapi/client_metrics.go` (`OriginPluginForcedDecision`)

## Gotchas

- Clients who can set the header can captcha or ban themselves. Empty default is the mitigation; put a previous middleware in front.
- Header `c` MUST NOT override a stream/live ban when lookup runs. Ban wins and WARN `ServeHTTP:forcedCaptchaSuperseded`. A LAPI exclude match skips lookup, so `c` captchas even if the store has a ban.
- Invalid captcha client still bans on `c` when lookup is not ban, same as stream captcha.
- Trusted `bouncerClientTrustedIPs` never see the header.
