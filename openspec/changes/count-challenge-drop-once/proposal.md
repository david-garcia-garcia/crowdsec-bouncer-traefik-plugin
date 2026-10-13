## Why

On master, every relayed AppSec envelope increments usage-metrics `dropped`. A visitor who solves a CrowdSec 1.8 bot-detection challenge therefore counts the page plus `fpscanner.js`, `pow-worker.js`, and `/crowdsec-internal/challenge/submit`. Upstream PR 403 point 5 asks that only the challenge page count once.

## What Changes

- A relay whose path is under `/crowdsec-internal/challenge/` MUST NOT increment `dropped` (request or bytes).
- The challenge page (any other path) still increments `dropped` once.
- Bans, `pkg/captcha`, and non-callback remediations stay counted as today.
- Fold `core_plugin_appsec_bot-detection` so `blockedRequests` SHALL increment no longer applies to that callback prefix.
- Do not add origin or remediation labels. Do not change the metrics POST shape.
- Regression: challenge envelope on `/protected` increments `TestDroppedCount` by 1; the same envelope on `/crowdsec-internal/challenge/submit` does not.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_bot-detection`: a challenge (or other AppSec) relay under `/crowdsec-internal/challenge/` does not increment `dropped`; any other path still increments once.

## Impact

- `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP` (path guard before `recordDropped`)
- `pkg/bouncer` tests using existing `TestDroppedCount`
- OpenSpec fold only `core_plugin_appsec_bot-detection`
- Delivery card MUST mention https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 5
- No **BREAKING** public JSON/YAML keys
- Out of scope: challenge-path 404, LAPI decision types, `.github/workflows`, closed PR 195, a new AppSec JSON parser, copying the upstream patch, origin/remediation labels, metrics POST shape
