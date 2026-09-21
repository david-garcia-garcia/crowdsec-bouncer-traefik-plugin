## Why

Operators cannot name one policy for “LAPI is down” and one for “AppSec is down.” On `master` those outcomes are split across `updateMaxFailure`, live lookups that always ban on LAPI error, and three AppSec booleans. CrowdSec’s bouncer spec already names `lapi_failure_action` and `appsec_failure_action`; this plugin should expose the same two actions, with the plugin’s existing `Crowdsec*` Config prefix.

## What Changes

- Add public `crowdsecLapiFailureAction` and `crowdsecAppsecFailureAction` (`passthrough` | `ban` | `captcha`). Default **`ban`** (this plugin’s fail-closed today, not CrowdSec spec passthrough).
- `CrowdsecLapiFailureAction` is the action on live LAPI error and on stream/alone cache miss while the stream is unhealthy. **Keep** `UpdateMaxFailure` as the stream poll counter (`-1` never unhealthy).
- **BREAKING:** `CrowdsecAppsecFailureAction` replaces `crowdsecAppsecFailureBlock`, `crowdsecAppsecUnreachableBlock`, and `crowdsecAppsecUnreadableBodyBlock`. YAML that still sets those bools is ignored; operators who had `false` MUST set `crowdsecAppsecFailureAction: passthrough`.
- `captcha` is valid only when a captcha provider is configured; otherwise ValidateParams fails. That path is `pkg/captcha`, not AppSec JSON `action: captcha` (relay stays as today).
- AppSec 200 / structured 403 envelopes are unchanged. `StreamStartupBlock` and `RedisCacheUnreachableBlock` are unchanged.

## Capabilities

### New Capabilities

- `core_plugin_lapi_failure-action`: Public `crowdsecLapiFailureAction` for live LAPI errors and stream-unhealthy cache misses; `UpdateMaxFailure` remains the stream unhealthy counter.
- `core_plugin_appsec_failure-action`: Public `crowdsecAppsecFailureAction` for AppSec HTTP 500, unreachable, and unreadable body; removes the three AppSec block booleans.

### Modified Capabilities

- `core_plugin_appsec_bot-detection`: HTTP 500 and unreachable honor `CrowdsecAppsecFailureAction` instead of `FailureBlock` / `UnreachableBlock`. Structured challenge relay is unchanged.

## Impact

- `pkg/configuration` — new keys, defaults, validate; drop three bool fields.
- `pkg/crowdsecconnection` — `AppsecPolicy` becomes an action enum; live lookup error; stream unhealthy still uses `UpdateMaxFailure`; identity includes `LapiFailureAction`.
- `pkg/bouncer` — stream miss and AppSec error dispatch `ban` / `passthrough` / `captcha`.
- README, examples, mock e2e AppSec yaml, tests.
- Reclaim: `CrowdsecLapiFailureAction` on CrowdsecConnection identity; `CrowdsecAppsecFailureAction` per-router on Bouncer.
