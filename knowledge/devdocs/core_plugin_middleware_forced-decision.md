# Forced decision header

## Language

**Forced decision header**:
The Config string `crowdsecDecisionHeader` naming an incoming request header whose exact trimmed values `b` (ban) and `c` (captcha) remediates without stream or live lookup. Empty means the feature is off. Not `decisionScopeHeaders` (CrowdSec identity). Not `remediationHeadersCustomName` (outgoing).
_Avoid_: BannedValue `t` as a public letter; treating the header as an address or AppSec action

## Overview

An earlier Traefik middleware can force this bouncer to ban or captcha. ServeHTTP reads the header after the trusted-client skip and calls the same remediator as a stream hit, so a valid captcha gate still passes origin while the header stays `c`.

## How to use

- Put `crowdsecDecisionHeader` on Config. Empty or whitespace is off; do not default a header name.
- Trim the name in `bouncer.New`. Read `Header.Get` after trusted skip, before appsec-mode and lookup.
- Map public `b` → `BannedValue`, `c` → `CaptchaValue`. Ignore every other token.
- Call `handleRemediationServeHTTP` with origin `plugin:forced_decision`. Do not strip the header.
- Do not put the letter on `clientRequest`. Client address stays `GetRemoteIP`.

## Pattern snippet

```go
if kind := b.forcedDecisionKind(req.Request); kind != "" {
	b.handleRemediationServeHTTP(rw, req, kind, lapi.OriginPluginForcedDecision)
	return
}
```

## Key files

- `pkg/configuration/configuration.go` (`CrowdsecDecisionHeader`)
- `pkg/bouncer/bouncer.go` (`forcedDecisionKind`, ServeHTTP)
- `pkg/lapi/client_metrics.go` (`OriginPluginForcedDecision`)

## Gotchas

- Clients who can set the header can captcha or ban themselves. Empty default is the mitigation; put a previous middleware in front.
- Invalid captcha client still bans on `c`, same as stream captcha.
- Trusted `clientTrustedIps` never see the header.
