# CaptchaBanOrigins

## Language

**CaptchaBanOrigins**:
Public Traefik Config `[]string` (`captchaBanOrigins`) copied onto `lapi.Client` at `New`. Empty is a no-op. A LAPI `ban` whose metrics origin matches an entry is stored as captcha kind `c`.
_Avoid_: remapping at ServeHTTP, matching raw `decision.Origin` without `MetricsOrigin`, putting this list on the reclaim Open key

**lists prefix match**:
Config entry `lists` matches metrics origin `lists` and any `lists:<name>`. Entry `lists:<name>` matches only that list. Other entries are exact equality on the metrics origin.
_Avoid_: treating `lists:foo` as a prefix of other lists, case-fold match

## Overview

Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/369 remaps on raw origin. This fork matches `MetricsOrigin` so operators can remap one CrowdSec list. Stream Ip/header, stream Range, and live/none query share `remediationKindForOrigin`. Live strongest pick uses the remapped kind so a still-ban wins. First `New` wins on a shared Client.

## How to use

- Copy trimmed non-empty entries in `lapi.New` (`copyCaptchaBanOrigins`). Do not hash them into `SessionKey` or live `Key`.
- Build origin with `MetricsOrigin` then `kind := c.remediationKindForOrigin(type, origin)` on stream Put, Range upsert, and live query.
- Prefer a remapped still-ban in `strongestLiveDecision`. Do not pick the first raw `Type=="ban"` then remap.
- Empty list: ban stays `t`. Unknown type stays empty (skip store). Captcha type stays captcha.
- Do not require `captchaProvider` here; missing provider still falls back to ban rendering.

## Pattern snippet

```go
origin := MetricsOrigin(item.Origin, item.Scenario)
kind := c.remediationKindForOrigin(item.Type, origin)
```

## Key files

- `pkg/configuration/configuration.go` (`CaptchaBanOrigins`)
- `pkg/lapi/captcha_ban_origins.go`
- `pkg/lapi/client.go` (`New` copy)
- `pkg/lapi/client_decisions.go`
- `pkg/lapi/client_stream.go`

## Gotchas

- Config `lists` remaps every list; `lists:firehol_level1` remaps one list.
- Two routers sharing a Client keep the first `New` list.
- Match is exact except the `lists` prefix rule. `capi` does not match `CAPI`.
