# OriginBasedDecisionRemap

## Language

**OriginBasedDecisionRemap**:
Public Traefik Config `map[string]map[string]string` (`originBasedDecisionRemap`) copied onto `lapi.Client` at `New`. Outer key is a metrics origin. Inner key is the original LAPI type (`ban` or `captcha`). Inner value is `captcha` or `pass`. Empty is a no-op. One hop on the original type; `pass` is skip store (AppSec still runs on the pass path).
_Avoid_: remapping at ServeHTTP, matching raw `decision.Origin` without `MetricsOrigin`, putting this table on the reclaim Open key, chaining two edges, calling `pass` allow

**lists prefix match**:
Config key `lists` matches metrics origin `lists` and any `lists:<name>`. Key `lists:<name>` matches only that list and wins over `lists`. Other keys are exact equality on the metrics origin.
_Avoid_: treating `lists:foo` as a prefix of other lists, case-fold match

## Overview

Stream Ip/header, stream Range, and live/none query share `remediationKind`. Live strongest pick uses the remapped kind so a still-ban wins. First `New` wins on a shared Client.

## How to use

- Copy trimmed weaken edges in `lapi.New` (`copyOriginBasedDecisionRemap`). Do not hash them into `SessionKey` or live `Key`.
- Build origin with `MetricsOrigin` then `kind := c.remediationKind(type, origin)` on stream Put, Range upsert, and live query.
- Prefer a remapped still-ban in `strongestLiveDecision`. Do not pick the first raw `Type=="ban"` then remap.
- Empty table: ban stays `t`, captcha stays `c`. Unknown type stays empty (skip store). `pass` is empty kind (skip store).
- Reject invalid edges in `ValidateParams`. Do not require `captchaProvider`; missing provider still falls back to ban rendering for stored captcha.

## Pattern snippet

```go
origin := MetricsOrigin(item.Origin, item.Scenario)
kind := c.remediationKind(item.Type, origin)
```

## Key files

- `pkg/configuration/configuration.go` (`OriginBasedDecisionRemap`)
- `pkg/configuration/origin_based_decision_remap.go`
- `pkg/lapi/origin_based_decision_remap.go`
- `pkg/lapi/client.go` (`New` copy)
- `pkg/lapi/client_decisions.go`
- `pkg/lapi/client_stream.go`

## Gotchas

- Config `lists` remaps every list; `lists:firehol_level1` remaps one list.
- Two routers sharing a Client keep the first `New` table.
- Match is exact except the `lists` prefix rule. `capi` does not match `CAPI`.
- `CAPI: {ban: captcha, captcha: pass}` stores a CAPI ban as captcha; it does not chain to pass.
