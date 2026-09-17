## Why

Upstream #337: when Traefik reaches AppSec through an L7 proxy and CrowdSec is down, the proxy returns HTTP 502/503/504. On v1.6.0 those statuses were treated as a generic non-200 AppSec verdict and banned even when the operator asked for passthrough. This tree already classifies those statuses as unreachable; there is no committed test that proves passthrough on HTTP 502/503/504.

## What Changes

- Add unit tests that AppSec HTTP 502, 503, and 504 honor `crowdsecAppsecFailureAction` (`passthrough` → allow, `ban` → error, `captcha` → `ErrFailureCaptcha`), same mapper as transport unreachable.
- Fold a named reverse-proxy scenario onto `core_plugin_appsec_failure-action` so those HTTP statuses are explicit in the spec, not only implied by the word "unreachable".
- Do not change product behavior unless a test cannot be honest without a one-line correctness fix.
- Do not add a second mock e2e scenario for passthrough. Existing e2e keeps default `ban` on 502.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_failure-action`: Name HTTP 502/503/504 from the AppSec listener as unreachable and require they honor `crowdsecAppsecFailureAction` the same way as a transport failure.

## Impact

- `pkg/appsec/failure_action_test.go` — table of reverse-proxy statuses × failure actions.
- `openspec/specs/core_plugin_appsec_failure-action/spec.md` — named reverse-proxy scenarios (archive sync).
- No public config change. No e2e mock YAML change.
