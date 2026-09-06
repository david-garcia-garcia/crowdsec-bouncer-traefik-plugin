## Why

On `master`, AppSec JSON `action: captcha` is parsed and relayed through `handleAppsecResponseServeHTTP`, but no test or spec scenario names that envelope. Upstream #357 reports missing captcha support; without proof, a regression can restore that gap silently.

## What Changes

- Add unit tests that parse `{"action":"captcha",...}` in `pkg/appsec` and relay status, body, headers, and cookies in `pkg/bouncer`.
- Cover the upstream no-body example `{"action":"captcha","http_status":403}` as empty-body relay (not operator ban, not `pkg/captcha`).
- Add those scenarios on existing `core_plugin_appsec_bot-detection`.
- Do not change product behavior unless a test cannot be honest without a one-line correctness fix.
- Do not add a solved-captcha cache knob. Not **BREAKING**.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_bot-detection`: AppSec JSON `action: captcha` SHALL parse like other structured envelopes and SHALL relay like challenge HTML. Empty captcha `user_body_content` SHALL still relay `http_status`; it MUST NOT ban and MUST NOT use `pkg/captcha`.

## Impact

- `pkg/appsec/query_test.go`
- `pkg/bouncer/bouncer_test.go`
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md` (archive sync)
- Plugin public config unchanged.
