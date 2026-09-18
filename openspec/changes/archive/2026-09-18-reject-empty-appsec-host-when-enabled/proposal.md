## Why

`ValidateParams` accepts `crowdsecAppsecEnabled: true` with an empty `crowdsecAppsecHost`. `plugin.New` then starts; every AppSec Query is unreachable and the default AppSec failure action bans the site.

## What Changes

- When AppSec is enabled, reject an empty `crowdsecAppsecHost` and any AppSec URL that `http.NewRequest` accepts only because the host is missing.
- Add a `ValidateParams` regression: enabled + empty host errors; disabled + empty host still passes.
- **Not BREAKING** for a default `New()` config (`crowdsecAppsecHost` is `crowdsec:7422`). Operators who enable AppSec and clear the host will fail at startup instead of serving a ban-on-every-request site.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: When AppSec is enabled, `ValidateParams` requires an AppSec listener host. Disabled-AppSec empty host and shared `validateURL` stay as they are.

## Impact

- `pkg/configuration/configuration.go` — `validateAppsecURLKeyAndTLS` only
- `pkg/configuration/zzz_configuration_test.go` — `ValidateParams` cases
