# Devdocs impact
change: modsecurity-leg

## Units
- Middleware New — subsystem — `plugin.go` / `openspec/changes/modsecurity-leg/specs/core_plugin_middleware_bouncer`
- Instance slots — subsystem — `pkg/reclaim` / `openspec/changes/modsecurity-leg/specs/core_plugin_middleware_instance-slots`
- Config validation — subsystem — `pkg/configuration` / `openspec/changes/modsecurity-leg/specs/core_plugin_middleware_config-validation`
- AppSec Client — subsystem — `pkg/appsec` / `openspec/changes/modsecurity-leg/specs/core_plugin_appsec_client`
- Action rules — subsystem — `pkg/httprule/action.go`
- HTTP request rules — pattern — `pkg/httprule`
- ModSecurity Client — subsystem — `pkg/modsecurity` / `openspec/changes/modsecurity-leg/specs/core_plugin_modsecurity_client`
- ModSecurity inspect — subsystem — `pkg/modsecurity/inspect.go` / `openspec/changes/modsecurity-leg/specs/core_plugin_modsecurity_inspect`
- Real-stack e2e — subsystem — `tests/e2e/real` / `openspec/changes/modsecurity-leg/specs/build_e2e_pester_crowdsec-stack`

## Findings
- [x] stale-usage  Middleware New — `core_plugin_middleware` still documents three reclaim legs
- [x] stale-usage  Instance slots — `core_plugin_middleware_instance-slots` still names three groups
- [x] stale-usage  Config validation — `core_plugin_middleware_config-validation` has no ModSec URL, E2, or backoff knobs
- [x] language-gap  AppSec Client — `core_plugin_appsec` has Query How-to, no Gate skip term
- [x] stale-usage  Action rules — `core_plugin_middleware_action-rules` missing `bypassModsec` and `serveModSec`
- [x] missing-packet  ModSecurity Client — no packet; new `pkg/modsecurity` reclaim owner
- [x] missing-packet  ModSecurity inspect — no packet; copy-then-classify protocol
- [x] stale-usage  Real-stack e2e — `build_e2e_real` still lists three Pester jobs

