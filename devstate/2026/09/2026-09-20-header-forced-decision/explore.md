# Explore
IssueKey: 2026-09-20-header-forced-decision

## Concepts

**Forced decision header**:
A config-named incoming request header whose value is a public letter `b` (ban) or `c` (captcha). Empty config name means the feature is off. Not `lapiScopeHeaders` (those headers are CrowdSec identity for stream/live lookup). Not `bouncerRemediationHeader` (outgoing).

**Header letter vs cache letter**:
Public contract is `b`/`c` as the ticket wrote. Dest cache letters stay `t`/`c`/`f` (`BannedValue` / `CaptchaValue` / `NoBannedValue` in `pkg/decisionscope/lookup.go`). Map `b` → `BannedValue` before `handleRemediationServeHTTP`. Do not teach other middlewares `t`.

**ServeHTTP insertion point**:
After GetRemoteIP + trusted-client skip. Header `b` remediates ban without lookup. Header `c` still consults stream/live lookup: a ban wins and WARN `ServeHTTP:forcedCaptchaSuperseded`; otherwise captcha via `handleRemediationServeHTTP` (gate still applies).

```
GetRemoteIP → trusted skip (unchanged)
    → bouncerDecisionHeader = b? → ban (no lookup)
    → else today’s lookup
         lookup ban + header c → ban + WARN
         else header c → captcha (gate still applies)
         else today’s remediator
```

**Owner of the letter**:
The configured header as set by an earlier Traefik middleware (or any hop that can write that request header). This plugin does not reconstruct a force from RemoteAddr, AppSec JSON, or the stream.

**Owner of client address**:
`ip.GetRemoteIP` (`core_plugin_ip.md`). Captcha gate HMAC still binds `req.remoteIP`. Force path does not parse identity from the decision header.

## Decisions

- Insert the force read on `Bouncer.ServeHTTP` after trusted-client skip. Reuse `handleRemediationServeHTTP`. Do not add a parallel captcha/ban router.
- Empty `bouncerDecisionHeader` (CreateConfig default) means off: do not read any default header name (clients would spoof `X-Crowdsec-Decision`).
- Header values: exact trimmed `b` and `c` only. Map `b` to `BannedValue`. Do not accept `t`, `ban`, `captcha`, or case variants.
- Missing header, empty value, or any other token: ignore and continue today’s lookup. Do not reject `New`. Do not fail the request.
- Skip `LookupRemediation` and `LiveLookup` only for header `b`. Header `c` still looks up; a ban wins and WARN; otherwise captcha. AppSec still runs only on the pass path after a gated-OK captcha.
- Trusted clients still skip the whole plugin (including the force header). Ticket did not ask to override that.
- Metrics origin for a forced drop: `plugin:forced_decision` (new `OriginPluginForcedDecision`). Ban template reason stays `ReasonLAPI` (same as stream captcha/ban via `handleRemediationServeHTTP`).
- Fold specs onto `core_plugin_middleware_bouncer` (ServeHTTP) and `core_plugin_middleware_config-validation` (optional header name). Captcha-routing leaf stays the gate owner; do not restate Check semantics there except a scenario that the force `c` path uses the same gate.

## Open questions

- Q: What is the public Config JSON/yaml key?
  Decision: assumed — `bouncerDecisionHeader` (string; empty = off). Sibling keys are `bouncerTraceHeader` / `lapiScopeHeaders`; this one names a CrowdSec decision letter, not identity or an outgoing remediation header. Example header name in docs: `X-Crowdsec-Decision`.
  By: explore

- Q: Is the header’s ban letter literal `b` or dest cache `t` (`BannedValue`)?
  Decision: assumed — public value is `b` as the ticket wrote; map to `BannedValue` internally. Other middlewares must not learn cache letters.
  By: explore

- Q: Missing, empty, or other values: ignore vs reject?
  Decision: assumed — ignore; continue stream/live/appsec as today. Only exact trimmed `b` or `c` force. Invalid tokens are not a constructor error.
  By: explore

- Q: Does “without querying the stream” also skip live/none `LiveLookup` and AppSec?
  Decision: resolved — `b` skips lookup. `c` still runs LookupRemediation / LiveLookup; a ban supersedes captcha and WARN `ServeHTTP:forcedCaptchaSuperseded`. AppSec still runs on pass after a gated-OK captcha; a forced ban never reaches AppSec.
  By: implement

- Q: Do trusted IPs still skip a forced header?
  Decision: assumed — yes. Trusted skip stays first; the ticket did not ask to apply the header to trusted clients.
  By: explore

- Q: What usage-metrics origin string for a forced drop?
  Decision: assumed — `plugin:forced_decision` (`OriginPluginForcedDecision`). Not `cscli` / `crowdsec` / `appsec`. Ban template reason remains `ReasonLAPI` via existing `handleRemediationServeHTTP`.
  By: explore

- Q: Who already owns client address / the force letter?
  Decision: assumed — client address: `ip.GetRemoteIP` (reuse; do not parse the decision header as an address). Force letter: the configured request header written by an earlier Traefik middleware; do not reconstruct from AppSec, stream, or RemoteAddr.
  By: explore
