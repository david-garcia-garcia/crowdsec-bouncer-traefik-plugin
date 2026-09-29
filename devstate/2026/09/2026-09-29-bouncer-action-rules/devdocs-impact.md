# Devdocs impact
change: bouncer-action-rules

## Units
- Action rules — subsystem — `pkg/httprule/action.go`, `pkg/bouncer` fold, Config `bouncerActionRules`; `openspec/specs/core_plugin_middleware_bouncer`
- HTTP request rules — subsystem — `pkg/httprule` `Matching`; `core_plugin_httprule`
- Middleware New — subsystem — `pkg/bouncer/bouncer.go`; `core_plugin_middleware`
- Config validation — subsystem — `ValidateParams` `BouncerActionRules`; `core_plugin_middleware_config-validation`
- LAPI usage-metrics — subsystem — origin `plugin:rules:<name>`; `core_plugin_lapi_usage-metrics`
- AppSec challenge — subsystem — `applyAppsecServeHTTP` overlay; `core_plugin_appsec`
- Forced decision header — removed unit — no remaining production surface; leftover YAML named only as unused keys

## Findings
- [x] stale-usage  Action rules — `core_plugin_middleware_action-rules` How-to never lists the five tokens or that `ban` must be alone
- [x] stale-usage  AppSec challenge — `core_plugin_appsec` Language and How-to still always relay a non-empty challenge
