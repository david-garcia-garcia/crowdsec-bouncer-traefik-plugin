## Why

`pkg/cache` owns CrowdSec remediation vocabulary (`t` / `c` / `f` / `d`) next to the string KV. Packages that apply a ban import the store to name those codes. Cache work stays coupled to remediations until the owners split.

## What Changes

- `pkg/decisionscope` owns ban / captcha / none codes (`BannedValue` = `t`, `CaptchaValue` = `c`, `NoBannedValue` = `f`).
- `pkg/captcha` owns captcha grace-done (`CaptchaDoneValue` = `d`).
- `pkg/cache` stays a string KV (Get / Set / Delete / GetMany, `CacheMiss`, `CacheUnreachable`) and does not export those four names.
- Call sites in bouncer, crowdsecconnection, decisionscope, captcha, and tests use the new owners.
- Wire bytes stay `t` / `c` / `f` / `d` so Redis and memory entries stay compatible. **Not BREAKING.**

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisions_scopes`: Ban, captcha, and none remediations are `pkg/decisionscope` codes with wire values `t` / `c` / `f`. LAPI types `ban` / `captcha` still map to those codes. Unknown types stay ignored.
- `core_cache_client_isolated-store`: The cache Client stores opaque strings. It MUST NOT export CrowdSec remediation names. Captcha grace payload `d` is owned by `pkg/captcha`.

## Impact

- `pkg/cache` (drop four consts; tests use opaque literals).
- `pkg/decisionscope` (declare `BannedValue` / `CaptchaValue` / `NoBannedValue` next to `RemediationValue`).
- `pkg/captcha` (declare `CaptchaDoneValue`).
- `pkg/bouncer`, `pkg/crowdsecconnection`, `plugin_test.go` call sites.
- Usage packets `knowledge/devdocs/core_plugin_decisionscope.md`, `knowledge/devdocs/core_cache_client.md`.
