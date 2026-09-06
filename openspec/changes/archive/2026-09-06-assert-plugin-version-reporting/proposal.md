## Why

Upstream tagged v1.6.0 and v1.7.0 while `pluginVersion` in source still named the previous release, so `cscli bouncers list` showed a stale version (#322, #363). This fork already bumps `version.go` before the tag, but nothing tests that LAPI usage-metrics `version` and LAPI/AppSec `User-Agent` carry that string. A future manual tag can regress the same failure undetected.

## What Changes

- Add httptest coverage that a LAPI Client reports the `pluginVersion` it was constructed with as `remediation_components[].version` and as `User-Agent: Crowdsec-Bouncer-Traefik-Plugin/<version>`.
- Add httptest coverage that AppSec Query uses the same User-Agent prefix plus that Client’s `pluginVersion`.
- Add a root-package test that `New` sends that User-Agent using the unexported `pluginVersion` from `version.go` (do not hardcode a release number).
- Do not change runtime reporting, export `pluginVersion`, or edit release workflows.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_usage-metrics`: Envelope identity scenarios SHALL lock `remediation_components[].version` and LAPI User-Agent to the plugin version passed into the Client, including the `version.go` value `plugin.go` `New` passes.
- `core_plugin_appsec_client`: AppSec Query SHALL set `User-Agent` to `Crowdsec-Bouncer-Traefik-Plugin/` plus the plugin version passed into the AppSec Client.

## Impact

- `pkg/lapi/metrics_test.go` (and/or a sibling LAPI test) — version field and User-Agent on the usage-metrics POST
- `pkg/appsec/query_test.go` — AppSec User-Agent
- `plugin_test.go` — `New` wiring from `version.go`
- No production code change unless a test cannot be honest without a one-line fix
