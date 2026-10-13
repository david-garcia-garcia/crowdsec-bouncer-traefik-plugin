# Requirement
IssueKey: 2026-09-20-header-forced-decision

## Problem
Other Traefik middlewares cannot force this plugin to ban or captcha a client. ServeHTTP always consults the stream cache (or live LAPI) before remediation. There is no config-gated incoming header whose value is ban or captcha and skips that lookup.

## Current (code)
- After trusted-IP skip, ServeHTTP reads `decisionScopeHeaders` as CrowdSec identity values, then `LookupRemediation` (live/stream/alone cache) or `LiveLookup` (live/none). No header value forces ban/captcha without that lookup. `pkg/bouncer/bouncer.go`
- `appsec` mode skips LAPI/stream and goes to the pass path. `pkg/bouncer/bouncer.go`
- Trusted client IPs skip LAPI and AppSec entirely. `pkg/bouncer/bouncer.go`
- Config has `decisionScopeHeaders` (scope name → request header for stream/live identity) and `remediationHeadersCustomName` (outgoing response header). No incoming force-decision header field. `pkg/configuration/configuration.go`
- Cache letters are `t` (ban), `c` (captcha), `f` (none). CrowdSec type `ban` maps to `t`, not `b`. `pkg/decisionscope/lookup.go`
- Captcha kind still honors the gate: `Check` true and not a captcha-form POST calls `handleNextServeHTTP`. `pkg/bouncer/bouncer.go` `pkg/captcha/captcha.go`
- Incoming `X-Crowdsec-Decision` (or any config key that reads a request header as `b`/`c` and skips stream): not found.

## Desired
- A feature enabled through config: when a named incoming request header is present (example name `X-Crowdsec-Decision`) with value `b` or `c` (ban or captcha only), apply that decision without querying the stream.
- Purpose: other middlewares can decide to CAPTCHA a client.
- Captcha gate still applies: if the header is `c` and the visitor already gated OK, the request goes through even though the header is still `c`.

## Affected
- `pkg/configuration/configuration.go` (new optional header-name key)
- `pkg/bouncer/bouncer.go` (`ServeHTTP` before stream/live lookup; reuse `handleRemediationServeHTTP`)
- `pkg/captcha` gate path (reuse `Check`; do not change gate semantics)
- README / Traefik examples for the new key
- OpenSpec for middleware request path and config validation (propose chooses fold vs new)

## Out of scope
- Changing `decisionScopeHeaders` or header-scope LAPI matching
- Changing outgoing `remediationHeadersCustomName`
- New captcha-gate cookie/HMAC behavior
- Header values other than ban and captcha
- Stripping the header before `next`
- Client-spoof mitigations beyond “enabled through config”
- AppSec JSON actions, Redis, metrics packing

## Unknowns
- Public config JSON/yaml key name (ticket only exemplifies the header name).
- Whether the header’s ban letter is literal `b` as the ticket wrote, or dest `t` (`BannedValue`).
- Missing, empty, or other values: ignore (today’s lookup) vs reject.
- Whether “without querying the stream” also skips live/none `LiveLookup` and AppSec.
- Whether trusted IPs still skip a forced header.
- Metrics origin string for a forced drop.

## Tensions
- Ticket values are `b`/`c`; dest ban letter is `t` (`BannedValue` in `pkg/decisionscope/lookup.go`).
- Ticket names stream skip; dest `ServeHTTP` also has live/none `LiveLookup` on the same path (`pkg/bouncer/bouncer.go`).
- Captcha-gate pass-through while kind stays captcha is already current for stream captcha (`handleRemediationServeHTTP` + `Check`); the ticket asks to keep that when an upstream middleware still sends `c`.
- Trusted IPs never reach header or stream logic today; the ticket does not say they should see the force header.
- `decisionScopeHeaders` is a different incoming-header feature (identity for lookup, not a force letter).
