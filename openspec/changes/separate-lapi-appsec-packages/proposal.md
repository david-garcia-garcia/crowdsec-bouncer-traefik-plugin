## Why

`pkg/crowdsecconnection` is one reclaim type for CrowdSec LAPI decisions and AppSec WAF. Developers cannot change one job without reading the other, and spec `core_plugin_connection_source-files` still forbids a new import path.

## What Changes

- Rename `pkg/crowdsecconnection` to `pkg/lapi`. The reclaim type is `lapi.Connection`. Drop exported `CrowdsecConnection`.
- Add `pkg/appsec` owning the AppSec HTTP client, `Query`, envelope types, and failure mapping.
- `plugin.go` Opens LAPI and AppSec separately. `Bouncer` holds both pointers. Neither package imports the other.
- LAPI live identity and stream settings no longer include AppSec fields. AppSec reclaim is its own key.
- `crowdsecMode: appsec` skips LAPI Open. AppSec Open runs when `crowdsecAppsecEnabled`.
- Supersede `core_plugin_connection_source-files` (that spec forbids the split).
- No **BREAKING** public JSON/YAML keys. Verdict protocol unchanged. Live Redis cache prefix changes once (AppSec dropped from `IdentityHex`).

## Capabilities

### New Capabilities

- `core_plugin_lapi_connection`: `pkg/lapi` owns the LAPI/CAPI reclaim Connection (decisions, stream, cache, metrics). No AppSec.
- `core_plugin_appsec_client`: `pkg/appsec` owns the AppSec reclaim Client (`Query`, envelope, failure mapping).

### Modified Capabilities

- `core_plugin_middleware_instance-reclaim`: two reclaim slots; LAPI identity excludes AppSec; stream warn-and-wire excludes AppSec; `appsec` mode skips LAPI Open.
- `core_plugin_connection_source-files`: remove the same-package AppSec and frozen import-path requirements (unit gone).
- `core_plugin_appsec_bot-detection`: `Query` lives on `appsec.Client`; client IP remains `pkg/ip.GetRemoteIP`.
- `core_plugin_appsec_failure-action`: AppSec fallback stays per-router; shared backend is `lapi.Connection`, not a mixed type.
- `core_plugin_lapi_failure-action`: shared LAPI fallback is on `lapi.Connection`.

## Impact

- `pkg/crowdsecconnection/` becomes `pkg/lapi/`. New `pkg/appsec/`.
- `plugin.go`, `plugin_test.go`, `pkg/bouncer`, `.golangci.yml` depguard paths.
- Usage packets `core_plugin_middleware.md` and `core_plugin_appsec.md`.
- Catalog folder `openspec/specs/core_plugin_connection_source-files/` is removed at archive after its requirements are deleted.
