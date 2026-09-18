## Why

`crowdsecMode: alone` returns after CAPI machine id and password, so it never calls `validateAppsecURLKeyAndTLS`. A garbage AppSec CA PEM or a missing AppSec key file starts. The spec already requires those AppSec checks and MAY-skips only LAPI URL, LAPI key, and LAPI TLS.

## What Changes

- After CAPI `GetVariable` on machine id and password, call `validateAppsecURLKeyAndTLS` in the alone branch. Do not call `validateLapiAndAppsecConnection` / `validateLapiURLAndKeys`.
- Keep skipping LAPI URL, LAPI key, and LAPI TLS in alone.
- Do not add an enabled-or-fields gate. Live/stream already always run the helper; default AppSec host `crowdsec:7422` already passes the URL check.
- Add `Test_ValidateParams` table rows: invalid AppSec CA in alone; missing AppSec key file in alone; existing alone+CAPI still ok.
- Fold those scenarios onto `core_plugin_middleware_config-validation`. Keep MAY-skip as LAPI-only.
- **Not BREAKING.** Valid alone+CAPI configs still start. Invalid AppSec URL, key file, or HTTPS CA that already fail in live/stream now fail in alone too.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: Alone SHALL still run AppSec URL, AppSec key-file, and AppSec HTTPS CA checks via `validateAppsecURLKeyAndTLS`. MAY-skip stays LAPI-only.

## Impact

- `pkg/configuration/configuration.go` (`ValidateParams` alone branch)
- `pkg/configuration/zzz_configuration_test.go` (`Test_ValidateParams` table)
- `openspec/specs/core_plugin_middleware_config-validation/spec.md`
- Out of scope: LAPI URL/key/TLS in alone; live/stream validator rewrite; AppSec client-cert parse at ValidateParams; `appsec.Prepare` / Open / reclaim / failure-action
