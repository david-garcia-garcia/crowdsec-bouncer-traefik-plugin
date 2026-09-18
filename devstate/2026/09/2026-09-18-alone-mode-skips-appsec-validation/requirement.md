# Requirement
IssueKey: 2026-09-18-alone-mode-skips-appsec-validation

## Problem
`crowdsecMode: alone` skips the whole LAPI+AppSec connection validator after CAPI credentials, so a garbage AppSec CA PEM and a missing AppSec key file pass startup. Spec allows skipping LAPI URL/key/TLS only. Hunt proof name: `TestHunt_ValidateParams_aloneModeStillRejectsInvalidAppsecCA`.

## Current (code)
- `ValidateParams` on `AloneMode` checks CAPI machine id and password, then does not call `validateLapiAndAppsecConnection`. `pkg/configuration/configuration.go:334-345`
- Live/stream/none/appsec take the `else` and run that helper. `pkg/configuration/configuration.go:341-344`
- `validateLapiAndAppsecConnection` is LAPI URL/key/TLS then `validateAppsecURLKeyAndTLS`. `pkg/configuration/configuration.go:412-417`
- `validateAppsecURLKeyAndTLS` always checks AppSec URL (effective scheme), `GetVariable` on `CrowdsecAppsecKey` (reads `CrowdsecAppsecKeyFile` when set), and AppSec CA PEM when scheme is `https` and insecure-verify is false. `pkg/configuration/configuration.go:455-477` `:220-239` `:532-546`
- Invalid AppSec CA PEM returns `failed parsing pem file`. `pkg/configuration/configuration.go:543-544`
- Missing key file returns `CrowdsecAppsecKey:<path> invalid path`. `pkg/configuration/configuration.go:226-229`
- Existing table includes "Alone mode with CAPI credentials" (want no error) and "AppSec HTTPS with invalid CA while LAPI HTTP" on a non-alone config (want error). No alone+invalid AppSec CA or missing AppSec key-file case. `pkg/configuration/zzz_configuration_test.go:123-126` `:135-138` `:183-187`
- Hunt test `TestHunt_ValidateParams_aloneModeStillRejectsInvalidAppsecCA` — not found
- Spec: AppSec HTTPS CA MUST be rejected; alone MAY skip LAPI URL/key/TLS only. `openspec/specs/core_plugin_middleware_config-validation/spec.md`

## Desired
After CAPI credential checks, if AppSec is enabled or AppSec TLS/key fields are set, run the same AppSec URL, key-file, and HTTPS CA checks as live/stream. Keep skipping LAPI URL/key/TLS in alone. Add regression tests. Bound to this defect.

## Affected
- `pkg/configuration/configuration.go`
- `pkg/configuration/zzz_configuration_test.go`
- `openspec/specs/core_plugin_middleware_config-validation/spec.md` (alone AppSec scenarios if propose adds them)

## Out of scope
- LAPI URL, LAPI key, and LAPI TLS checks in alone
- Captcha, logging, and other ValidateParams helpers
- Hunt #15 log-file FD leak and #16 empty AppSec host in other modes
- Runtime AppSec client, reclaim, or failure-action behavior
- Changing live/stream validation

## Unknowns
- Hunt proof is a name, not an in-tree test
- Ticket gates AppSec checks on enabled or TLS/key fields; live/stream always call `validateAppsecURLKeyAndTLS`

## Tensions
- Spec MAY-skip list is LAPI-only; code skips AppSec with it
- Spec AppSec CA requirement is not mode-scoped; the alone branch never reaches it
- Ticket’s enabled-or-fields gate is narrower than the live/stream always-on AppSec URL check
