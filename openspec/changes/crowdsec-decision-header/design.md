## Context

See proposal.md Why. ServeHTTP after GetRemoteIP and the trusted-client skip always looks up (`pkg/bouncer/bouncer.go`). Captcha kind already passes origin when `Check` is true (`handleRemediationServeHTTP`). Dest cache letters are `t`/`c`/`f`; the ticket's public letters are `b`/`c`. Client address stays `ip.GetRemoteIP`.

## Goals / Non-Goals

**Goals:**
- Optional header name on Config; empty default off.
- Public letters `b`/`c` mapped to `BannedValue`/`CaptchaValue` before the existing remediator.
- Skip LookupRemediation and LiveLookup on a hit, including `crowdsecMode: appsec`.
- Captcha gate unchanged.

**Non-Goals:**
- New ValidateParams rejection of the header name.
- Stripping the header before `next`.
- Client-spoof mitigations beyond “empty = off”.
- Changing `decisionScopeHeaders`, outgoing `remediationHeadersCustomName`, Redis, AppSec JSON actions.
- Accepting cache letter `t` as a public value.

## Decisions

1. Config JSON key `crowdsecDecisionHeader` (string). Sibling incoming names use `*HeadersCustomName`; this key names a CrowdSec decision letter, not identity. Alternative `forcedDecisionHeader` rejected as less CrowdSec-prefixed than neighbors like `crowdsecLapiFailureAction`.
2. Read `req.Header.Get` after trusted skip, before the appsec-mode short-circuit. Alternative: after lookup — rejected; that would still query the stream.
3. Exact trimmed `b`/`c` only. Map `b` → `BannedValue` then call `handleRemediationServeHTTP` with origin `plugin:forced_decision`. Alternative: accept `t` — rejected so other middlewares do not learn cache letters.
4. Invalid/missing values fall through. Alternative: fail-closed — rejected; garbage or client junk must not ban.
5. Trusted skip stays first. Alternative: force header overrides trusted — rejected; ticket did not ask.
6. Ban template reason stays `ReasonLAPI` (existing remediator). Metrics origin is the new plugin string.

## Risks / Trade-offs

- [Clients can send `c` or `b` when the operator publishes the header name] → Mitigation: empty default; README says put a previous middleware in front and do not expose the header to the internet.
- [Header `c` with invalid captcha client still bans] → Mitigation: same as stream captcha today (`handleRemediationServeHTTP` bans when captcha is not Valid).

## Migration Plan

Default empty. Operators set `crowdsecDecisionHeader: X-Crowdsec-Decision` (or another name) and place a middleware that writes `b` or `c` earlier in the Traefik chain. Rollback: omit the key.

## Open Questions

None — explore assumed rows stand.
