## Why

`ValidateParams` validates AppSec URL, key file, and HTTPS CA in live/stream even when `crowdsecAppsecEnabled` is false, so leftover missing `crowdsecAppsecKeyFile` or explicit-https garbage CA can fail a router that has AppSec off. Alone skips the whole LAPI+AppSec validator, so AppSec-on plus garbage CA or missing key file still boots; default AppSec failure action is ban and those requests drop at runtime.

## What Changes

- In every mode, call `validateAppsecURLKeyAndTLS` only when `config.CrowdsecAppsecEnabled` is true. Do not invent a second enabled signal (leftover fields, `crowdsecMode: appsec`).
- Alone still skips LAPI URL, key, and TLS after CAPI machine id and password. Live, stream, none, and appsec still validate LAPI.
- Do not validate AppSec host/URL/key/CA when the knob is false, even if leftover fields are set.
- Flip dest table case "AppSec HTTPS with invalid CA while LAPI HTTP" to success (AppSec off leftover CA). Add alone + AppSec on fail, alone + AppSec off leftover success, live/stream + AppSec on still fail, and set enabled on the distinct-scheme URL case.
- **Not BREAKING** for routers that already have AppSec on with valid URL/key/CA. Startups that leave AppSec off with leftover invalid CA or a missing key file now boot. Alone + AppSec on with garbage CA or a missing key file now fail closed.
- Do not reuse declined PR #80 / branch `2026-09-18-alone-mode-skips-appsec-validation` (always validated AppSec knobs in alone even when AppSec was off).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: gate AppSec URL, key-file, and HTTPS CA checks on `crowdsecAppsecEnabled` in every mode; leftover invalid CA / missing key file succeeds when the knob is false; alone still skips LAPI only.

## Impact

- `pkg/configuration/configuration.go` (`ValidateParams`, `validateLapiAndAppsecConnection`)
- `pkg/configuration/zzz_configuration_test.go`
- `openspec/specs/core_plugin_middleware_config-validation/spec.md` (enabled-gate scenarios)
