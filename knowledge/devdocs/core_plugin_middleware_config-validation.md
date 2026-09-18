# Config validation

## Language

**ValidateParams**:
The constructor-time check of Traefik-owned `*configuration.Config` that `New` runs on the prepared snapshot before `lapi.Prepare` / `appsec.Prepare`.
_Avoid_: `appsec.Prepare`, `lapi.Prepare`, Open, ServeHTTP

## Overview

`pkg/configuration.ValidateParams` rejects a bad Traefik Config before any reclaim Open. Spec: `core_plugin_middleware_config-validation`. New sequence: `core_plugin_middleware.md`. AppSec Open after this check: `core_plugin_appsec.md`.

## How to use

- Call `configuration.ValidateParams` on New's snapshot before `lapi.Prepare` / `appsec.Prepare`.
- Alone: after CAPI `GetVariable` on machine id and password, call `validateAppsecURLKeyAndTLS` only. Do not call `validateLapiAndAppsecConnection` or `validateLapiURLAndKeys`.
- Live/stream/none/appsec: call `validateLapiAndAppsecConnection` (LAPI URL, LAPI key, LAPI TLS, then the same AppSec helper).
- Always run the AppSec helper. Do not gate it on `crowdsecAppsecEnabled` or on AppSec TLS/key fields.
- Reuse `validateAppsecURLKeyAndTLS` for the AppSec URL (effective scheme), `GetVariable("CrowdsecAppsecKey")` (a set `CrowdsecAppsecKeyFile` must exist), and HTTPS CA PEM. Do not copy those checks into `appsec.Prepare` or New.
- Trigger AppSec CA parse on explicit `CrowdsecAppsecScheme == https` (and insecure-verify off), not on `effectiveAppsecScheme`.
- Leave secret copy and scheme fallback to `appsec.Prepare` after this check.

## Pattern snippet

```go
if config.CrowdsecMode == AloneMode {
	if err := validateAloneCapiAndAppsec(config); err != nil {
		return err
	}
} else {
	if err := validateLapiAndAppsecConnection(config); err != nil {
		return err
	}
}
```

## Key files

- `pkg/configuration/configuration.go`
- `plugin.go`
- `openspec/specs/core_plugin_middleware_config-validation/spec.md`

## Gotchas

- Always-on AppSec URL check in alone rejects a bad default host even when AppSec is off. Default `crowdsecAppsecHost` `crowdsec:7422` already passes.
- Empty AppSec key is allowed here; `appsec.Prepare` later copies `CrowdsecLapiKey` (often empty in alone).
- Alone MAY skip LAPI URL, LAPI key, and LAPI TLS. It MUST NOT skip AppSec URL, AppSec key-file, or AppSec HTTPS CA.
