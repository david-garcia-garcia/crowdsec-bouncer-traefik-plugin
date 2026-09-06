## Context

See proposal.md — Why. Today `HTTPTimeoutSeconds` is copied into three `http.Client.Timeout` values and into AppSec reclaim identity as raw seconds. Traefik plugin `Config` has no float or pointer fields; durations are `int64` with the unit in the JSON name. Official CrowdSec bouncer spec uses a separate `appsec_timeout` (default 200ms); this plugin's CreateConfig default stays inherit so existing deploys do not shorten AppSec.

## Goals / Non-Goals

**Goals:**

- One owner for “what duration does AppSec HTTP use”
- Millisecond granularity without a second seconds field
- Reclaim key follows the duration the client actually uses

**Non-Goals:**

- LAPI or captcha millisecond knobs
- Changing AppSec CreateConfig default to 200ms
- E2E hanging-AppSec appliance

## Decisions

- **Field `CrowdsecAppsecTimeoutMilliseconds int64`.** Alternatives: ticket’s `AppsecTimeoutSeconds` (no `CrowdsecAppsec` prefix; seconds are coarse); float seconds (no float fields on `Config`; Traefik labels are strings). Zero means unset because CreateConfig/`New()` leave it at 0 and `omitempty` omits it.
- **`configuration.EffectiveAppsecTimeout(*Config) time.Duration`.** AppSec `New` and identity both call it. Do not duplicate inherit math. If milliseconds > 0, return that many `time.Millisecond`; else `HTTPTimeoutSeconds * time.Second`.
- **Identity stores the effective millisecond count**, replacing `HTTPTimeoutSeconds` on the AppSec identity struct. Alternatives: hash both raw fields (two routers with inherit 10s vs explicit 10000ms would split clients with the same Timeout). LAPI identity still hashes `HTTPTimeoutSeconds`.
- **Validate `CrowdsecAppsecTimeoutMilliseconds >= 0`.** Not in the `requiredInt1` map (that map rejects 0). Negative fails. Zero is inherit.
- **Tests:** configuration inherit/override/negative; `appsec.New` against a hanging httptest server with 50ms timeout and passthrough, asserting elapsed well under `HTTPTimeoutSeconds`; identity hex equal for inherit 10s vs explicit 10000ms.

## Risks / Trade-offs

- [Changing AppSec identity JSON drops `httpTimeoutSeconds` for the hashed payload] → Existing AppSec slots keyed on LAPI seconds get a new hash on reload; Traefik `New` reclaim grace (30s) covers the handoff. Same as any identity field change.
- [Operators expecting ticket name `AppsecTimeoutSeconds`] → README documents `crowdsecAppsecTimeoutMilliseconds`; YAML/labels use that key. Prefix matches every other AppSec knob.
- [1ms minimum when set can be too aggressive] → Operator chose it; omit still yields the LAPI timeout.

## Migration Plan

- Omit the new key: behavior matches `master`.
- To shorten AppSec only: set `crowdsecAppsecTimeoutMilliseconds` (200 recommended for CrowdSec spec-style hang) and keep `httpTimeoutSeconds` long for stream.
- Rollback: remove the key (or revert the plugin); AppSec uses `httpTimeoutSeconds` again.

## Open Questions

None. Explore assumed rows stand.
