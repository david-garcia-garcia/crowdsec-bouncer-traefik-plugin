# Devdocs impact
change: bouncer-instance-severance

## Units
- Instance slots — subsystem — `pkg/instance` / `core_plugin_middleware_instance-slots`
- Middleware New — subsystem — `plugin.go` / `core_plugin_middleware`
- LAPI reclaim key — subsystem — `pkg/lapi` / `core_plugin_lapi_reclaim-key`
- AppSec Client — subsystem — `pkg/appsec` / `core_plugin_appsec`
- Config validation — subsystem — `pkg/configuration` / `core_plugin_middleware_config-validation`
- Reclaim table — pattern — `pkg/reclaim` / `std_go_reclaim`

## Findings
- [x] stale-usage  Instance slots — `core_plugin_middleware_instance-slots` How-to still requires publisher match on Clear; apply clears by dying pointer and adds ClearPublisher
- [x] stale-usage  Middleware New — `core_plugin_middleware` How-to omits ClearPublisher after PublishAll when a leg is not opened
