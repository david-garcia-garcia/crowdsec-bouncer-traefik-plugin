# Forced decision header

## Language

**Forced decision header**:
The Config string `crowdsecDecisionHeader` naming an incoming request header whose exact trimmed values `b` (ban) and `c` (captcha) force that remediation. Ban skips stream/live lookup. Captcha still looks up so an existing ban wins. Empty means the feature is off. Not `decisionScopeHeaders` (CrowdSec identity). Not `remediationHeadersCustomName` (outgoing).
_Avoid_: BannedValue `t` as a public letter; treating the header as an address or AppSec action

## Overview

An earlier Traefik middleware can force this bouncer to ban or captcha. ServeHTTP reads the header after the trusted-client skip. `b` remediates without lookup. `c` still consults stream/live lookup so a CrowdSec ban wins (WARN `ServeHTTP:forcedCaptchaSuperseded`); otherwise captcha reuses the gate.

## How to use

- Put `crowdsecDecisionHeader` on Config. Empty or whitespace is off; do not default a header name.
- Trim the name in `bouncer.New`. Read `Header.Get` after trusted skip, before appsec-mode and lookup.
- Map public `b` → `BannedValue`, `c` → `CaptchaValue`. Ignore every other token.
- Header `b`: call `handleRemediationServeHTTP` with origin `plugin:forced_decision` and return.
- Header `c`: still look up. If lookup (or fail-closed ban) is ban, WARN `ServeHTTP:forcedCaptchaSuperseded` and apply that ban. Otherwise captcha with origin `plugin:forced_decision`.
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

- `pkg/configuration/configuration.go` (`CrowdsecDecisionHeader`)
- `pkg/bouncer/bouncer.go` (`forcedDecisionKind`, ServeHTTP)
- `pkg/lapi/client_metrics.go` (`OriginPluginForcedDecision`)

## Gotchas

- Clients who can set the header can captcha or ban themselves. Empty default is the mitigation; put a previous middleware in front.
- Header `c` MUST NOT override a stream/live ban. Ban wins and WARN `ServeHTTP:forcedCaptchaSuperseded`.
- Invalid captcha client still bans on `c` when lookup is not ban, same as stream captcha.
- Trusted `clientTrustedIps` never see the header.
