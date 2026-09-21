# Requirement
IssueKey: 2026-09-18-appsec-validate-when-enabled

## Problem
`ValidateParams` validates AppSec URL, key file, and HTTPS CA in live/stream even when `appsecEnabled` is false, so leftover missing `appsecKeyFile` or explicit-https garbage CA can fail a router that has AppSec off. Alone skips the whole LAPI+AppSec validator, so AppSec-on plus garbage CA or missing key file still boots; default AppSec failure action is ban and those requests drop at runtime.

## Current (code)
- `New()` defaults `AppsecEnabled` to false and `BouncerAppsecFailureAction` to ban. `pkg/configuration/configuration.go`
- `ValidateParams` on `AloneMode` checks CAPI machine id and password, then does not call `validateLapiAndAppsecConnection`. `pkg/configuration/configuration.go`
- Live, stream, none, and appsec take the `else` and always call `validateLapiAndAppsecConnection`. `pkg/configuration/configuration.go`
- `validateLapiAndAppsecConnection` is LAPI URL/key/TLS then always `validateAppsecURLKeyAndTLS` with no enabled gate. `pkg/configuration/configuration.go`
- `validateAppsecURLKeyAndTLS` never reads `AppsecEnabled`. It validates AppSec URL (effective scheme), `GetVariable` on `AppsecKey` (reads `AppsecKeyFile` when set), and AppSec CA PEM when scheme is explicit `https` and insecure-verify is false. `pkg/configuration/configuration.go`
- Missing key file returns `AppsecKey:<path> invalid path`. `pkg/configuration/configuration.go`
- Invalid AppSec CA PEM returns `failed parsing pem file`. `pkg/configuration/configuration.go`
- Table case "AppSec HTTPS with invalid CA while LAPI HTTP" uses `getMinimalConfig()` (AppSec off) and wants an error. `pkg/configuration/zzz_configuration_test.go`
- No alone+AppSec-on invalid CA / missing key-file case, and no live/stream+AppSec-off leftover-CA success case. `pkg/configuration/zzz_configuration_test.go`
- Spec AppSec URL and HTTPS CA requirements have no `appsecEnabled` gate. `openspec/specs/core_plugin_middleware_config-validation/spec.md`
- Spec alone MAY skip LAPI URL/key/TLS only. `openspec/specs/core_plugin_middleware_config-validation/spec.md`

## Desired
- In all modes: if `config.AppsecEnabled` then `validateAppsecURLKeyAndTLS`.
- Alone still skips LAPI URL/key/TLS; still requires CAPI machine id and password.
- Live/stream still validate LAPI; AppSec checks only when enabled.
- Do not validate AppSec host/URL/key/CA when the enabled knob is false, even if leftover fields are set.
- Tests: alone + AppSec on + invalid CA or missing key file fails; alone + AppSec off + leftover invalid CA / missing key file succeeds (CAPI ok); live or stream + AppSec off + leftover invalid CA / missing key file succeeds (LAPI ok; intentional vs dest); live or stream + AppSec on + invalid CA / missing key file still fails.
- Update existing tests or specs that assumed live/stream always validate AppSec when off.

## Affected
- `pkg/configuration/configuration.go`
- `pkg/configuration/zzz_configuration_test.go`
- `openspec/specs/core_plugin_middleware_config-validation/spec.md` (enabled-gate scenarios)

## Out of scope
- Empty-host (#89) and other AppSec URL shape work unless a test update is required
- LAPI URL, LAPI key, and LAPI TLS checks in alone
- Runtime AppSec client, reclaim, or failure-action behavior
- Captcha, logging, Redis password-file gate
- Reusing closed PR #80 or branch `2026-09-18-alone-mode-skips-appsec-validation`

## Unknowns
- Redis leftover-password analog is the desired rule; dest still always `GetVariable`s `LapiRedisPassword`. `pkg/configuration/configuration.go`
- Spec "invalid AppSec host fails" WHEN clause does not name enabled; implement will add the gate, not empty-host shape.

## Tensions
- Dest spec SHALL reject invalid AppSec CA / validate AppSec URL with no enabled gate; ticket wants the gate and an intentional live/stream behavior change.
- Existing test "AppSec HTTPS with invalid CA while LAPI HTTP" assumes AppSec-off leftover CA fails.
- Declined PR #80 always validated AppSec knobs in alone even when AppSec was off; this ticket forbids that.
- Spec alone MAY-skip list is LAPI-only; dest alone also skips AppSec.
