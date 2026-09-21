# BouncerDecisionRemap

## Language

**BouncerDecisionRemap**:
Public Traefik Config `map[string]map[string]string` (`bouncerDecisionRemap`) copied onto each `bouncer.Bouncer` at `New`. Outer key is a metrics origin. Inner key is the original LAPI type (`ban` or `captcha`). Inner value is `captcha` or `pass`. Empty is a no-op. One hop on the stored letter at ServeHTTP; `pass` is no LAPI remediation (AppSec still runs). LAPI and the DecisionStore keep the original kind.
_Avoid_: remapping at stream Put or live cache, matching raw `decision.Origin` without `MetricsOrigin`, putting this table on the reclaim Open key, chaining two edges, calling `pass` allow, copying the table onto `lapi.Client`

**lists prefix match**:
Config key `lists` matches metrics origin `lists` and any `lists:<name>`. Key `lists:<name>` matches only that list and wins over `lists`. Other keys are exact equality on the metrics origin.
_Avoid_: treating `lists:foo` as a prefix of other lists, case-fold match

## Overview

Stream Ip/header, stream Range, and live/none query store `RemediationValue` only. Each router applies `applyBouncerDecisionRemap` after a successful lookup or live query. Live strongest pick uses the LAPI type so a still-ban wins in the shared cache. Two Bouncers on one Client may disagree.

## How to use

- Copy trimmed weaken edges in `bouncer.New` (`copyBouncerDecisionRemap`). Do not hash them into `SessionKey` or live `Key`. Do not copy them onto `lapi.Client`.
- Store with `MetricsOrigin` then `kind := decisionscope.RemediationValue(type)` on stream Put, Range upsert, and live query.
- After a successful `LookupRemediation` or `LiveLookup`, call `appliedLAPIRemediation` before `IsActiveRemediation`. Resolve packed origin ids when the table is non-empty.
- Empty table: ban stays `t`, captcha stays `c`. Unknown type stays empty (skip store). `pass` applies as `NoBannedValue`.
- Reject invalid edges in `ValidateParams`. Do not require `bouncerCaptchaProvider`; missing provider still falls back to ban rendering for applied captcha.

## Pattern snippet

```go
kind, origin, originID, err := b.lapiClient.LookupRemediation(req.remoteIP, req.ipAddr, scopes)
// ... handle err ...
kind, origin = b.appliedLAPIRemediation(kind, origin, originID)
```

## Key files

- `pkg/configuration/configuration.go` (`BouncerDecisionRemap`)
- `pkg/configuration/origin_based_decision_remap.go`
- `pkg/bouncer/origin_based_decision_remap.go`
- `pkg/bouncer/bouncer.go` (`New` copy, ServeHTTP apply)
- `pkg/lapi/client_decisions.go` (store `RemediationValue`)
- `pkg/lapi/client_stream.go`

## Gotchas

- Config `lists` remaps every list; `lists:firehol_level1` remaps one list.
- Two routers sharing a Client each apply their own table.
- Match is exact except the `lists` prefix rule. `capi` does not match `CAPI`.
- `CAPI: {ban: captcha, captcha: pass}` applies a stored CAPI ban as captcha; it does not chain to pass.
- Lookup still collapses on stored (LAPI) strength: an Ip ban skips Range membership before this router remaps.
