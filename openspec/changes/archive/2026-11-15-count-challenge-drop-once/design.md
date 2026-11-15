## Context

See `proposal.md` — Why. Dest `handleAppsecResponseServeHTTP` always calls `recordDropped(req, "appsec", "")` (`pkg/bouncer/bouncer.go`). `recordDropped` increments both the request and byte series. Ban and plugin captcha use the other two call sites. Master already parses and relays challenge JSON; do not add a parser.

FindSpecHost (propose, before folder write):

```
verdicts:
  - { deltaId: challenge-callback-drop-skip, fold, spec-id: core_plugin_appsec_bot-detection, confidence: high, candidates: [core_plugin_appsec_bot-detection, core_plugin_lapi_usage-metrics] }
```

Small adjustment: MODIFIED one requirement on the existing bot-detection leaf (path exception on `dropped`). Do not fold usage-metrics (ticket names the bot-detection spec; POST shape unchanged). Do not silent-rename `core_plugin_appsec_bot-detection`.

## Goals / Non-Goals

**Goals:**

- Skip `recordDropped` when `req.URL.Path` has prefix `/crowdsec-internal/challenge/`.
- Keep counting the challenge page and every non-relay remediation.

**Non-Goals:**

- Challenge-path 404; new JSON parser; copying upstream PR 403; origin/remediation labels; metrics POST shape; skip inside `recordDropped`.

## Decisions

1. **Guard only in `handleAppsecResponseServeHTTP`.** `strings.HasPrefix(req.URL.Path, "/crowdsec-internal/challenge/")` then skip `recordDropped`. Skipping that call skips both request and bytes. Alternative: skip inside `recordDropped` — rejected (would affect ban and `pkg/captcha`). Alternative: skip only when `action == challenge` — rejected (explore: skip is path-based on the shared relay).

2. **Prefix includes the trailing slash.** Exact `/crowdsec-internal/challenge` still counts. CrowdSec callbacks are `/challenge/submit`, `/challenge/fpscanner.js`, `/challenge/pow-worker.js`. Alternative: `PathPrefix(/crowdsec-internal/challenge)` without slash — rejected (ticket text is under `/crowdsec-internal/challenge/`).

3. **Path owner is `req.URL.Path`.** Same field httprule matches. Do not parse `RequestURI`.

4. **Tests use existing `TestDroppedCount`.** Bind LAPI metrics on the AppSec challenge helper. One case `/protected` = 1; one case `/crowdsec-internal/challenge/submit` = 0. Do not invent a second metrics helper.

5. **Usage packet after apply if dest usage claims every relay increments.** Propose does not rewrite `knowledge/devdocs/core_plugin_appsec.md` (consume: dest does not document dropped on relay). Implement / devdocs-impact updates it only if that packet is then wrong.

## Risks / Trade-offs

- **[Risk] An AppSec captcha envelope on the callback prefix also skips dropped** → Mitigation: accepted in explore; ban and `pkg/captcha` never enter this function.
- **[Trade-off] Do not copy PR 403** → Accepted; implement from this seam on master.

## Migration Plan

Single deploy. No public config. Rollback is revert.

## Open Questions

None. Proceed policies live on `devstate/explore.md`.
