## Why

`ValidateParams` lets misconfigured plugins start: AppSec URL/TLS is checked against LAPI settings or skipped, alone mode returns before captcha/template/log checks that still apply, and several validation branches lack tests. Startup should reject these configs before Traefik serves traffic.

## What Changes

- Validate AppSec URL using effective scheme (`CrowdsecAppsecScheme` when set, else `CrowdsecLapiScheme`).
- When AppSec scheme is explicitly HTTPS and verify is enabled, parse AppSec CA PEM at startup like LAPI HTTPS today.
- Restructure alone mode so captcha credentials/templates, ban template, and logging checks run before the alone-only early return from LAPI connection checks.
- Add focused unit tests for the gaps listed in the bug-hunt findings.

## Capabilities

### New Capabilities

- `core_plugin_middleware_config-validation`: Startup validation rules for plugin configuration in `pkg/configuration`.

### Modified Capabilities

## Impact

- `pkg/configuration/configuration.go` — `ValidateParams`, TLS/URL helpers, alone-mode ordering.
- `pkg/configuration/configuration_test.go` — new test cases.
